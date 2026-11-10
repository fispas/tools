#!/usr/bin/env bash
# =============================================================================
# vrepo-setup.sh - configurazione guidata di un hardened repository Veeam su Ubuntu
#
# iSCSI (initiator, discovery, login automatico, CHAP), multipath (profilo QNAP
# o generico, alias per LUN), LUN (GPT, XFS reflink, fstab per UUID, mount
# protetto), utente Veeam con sudo temporaneo, blindatura dopo l'aggiunta in VBR,
# riapertura temporanea per gli aggiornamenti Veeam, disconnessione dei target.
#
# Uso:  sudo ./vrepo-setup.sh                  wizard interattivo (menu)
#       sudo ./vrepo-setup.sh --help           tutti i comandi e le opzioni
#
# Repo: fispas/tools (backup/veeam-hardened-repo)
# =============================================================================
set -o pipefail
umask 022
export LC_ALL=C.UTF-8 2>/dev/null || export LC_ALL=C

VERSION="1.0.0"
BT="Veeam Hardened Repository - vrepo-setup $VERSION"
STATE_DIR=/etc/vrepo-setup
STATE_REPOS=$STATE_DIR/repos          # nome|wwid|uuid|mount
STATE_ALIASES=$STATE_DIR/aliases      # wwid|alias multipath
STATE_MPPROFILE=$STATE_DIR/multipath-profile
SAVED_CONF=$STATE_DIR/vrepo.conf
LOG_FILE=/var/log/vrepo-setup.log
INSTALL_PATH=/usr/local/sbin/vrepo-setup.sh
SUDOERS_FILE=/etc/sudoers.d/90-vrepo-setup
KEY_COMMENT=vrepo-setup
MP_MARK="# vrepo-setup: file generato"

DRY_RUN=0
GUI=0
INTERACTIVE=0
ASSUME_YES=0
CONFIG_FILE=""
OPT_DEV=""
OPT_WWID=""
OPT_NAME=""
OPT_MOUNT=""
OPT_TARGET=""
WARNINGS=0
ERRORS=0

# ------------------------------------------------------------- configurazione
CONFIG_KEYS="INITIATOR_NAME ISCSI_PORTALS ISCSI_PORT ISCSI_TARGETS ONLY_LISTED_PORTALS CHAP_USER CHAP_PASSWORD
MULTIPATH MULTIPATH_PROFILE MULTIPATH_ALIAS LUN_PREFIX LUN_NAMES MOUNT_BASE PARTITION FORCE_FORMAT
VEEAM_USER VEEAM_PASSWORD NTP_SERVERS TIMEZONE SSH_DISABLE LOCK_VEEAM_PASSWORD LOCKDOWN_FORCE
REMOVE_TARGETS REMOVE_DISCOVERY ADMIN_USER"
SECRET_KEYS=" CHAP_PASSWORD VEEAM_PASSWORD "

CFG_INITIATOR_NAME=""        # vuoto = mantiene quello attuale
CFG_ISCSI_PORTALS=""         # IP del target, separati da spazio/virgola (uno per percorso)
CFG_ISCSI_PORT="3260"
CFG_ISCSI_TARGETS=""         # IQN o caratteri jolly; vuoto = tutti quelli scoperti
CFG_ONLY_LISTED_PORTALS="yes" # login solo sui portali indicati (non sugli altri IP del NAS)
CFG_CHAP_USER=""
CFG_CHAP_PASSWORD=""
CFG_MULTIPATH="auto"         # auto | yes | no
CFG_MULTIPATH_PROFILE="qnap" # qnap | generic
CFG_MULTIPATH_ALIAS="yes"    # alias multipath = nome della LUN
CFG_LUN_PREFIX="veeam-repo"
CFG_LUN_NAMES=""             # wwid=nome;sdb=nome;...
CFG_MOUNT_BASE="/mnt"
CFG_PARTITION="yes"
CFG_FORCE_FORMAT="no"
CFG_VEEAM_USER="veeambck"
CFG_VEEAM_PASSWORD=""        # vuoto = generata
CFG_NTP_SERVERS=""
CFG_TIMEZONE=""
CFG_SSH_DISABLE="yes"
CFG_LOCK_VEEAM_PASSWORD="yes"
CFG_LOCKDOWN_FORCE="no"
CFG_REMOVE_TARGETS=""
CFG_REMOVE_DISCOVERY="no"
CFG_ADMIN_USER=""

# ------------------------------------------------------------------- log
_log() {
    local lvl=$1; shift
    local msg="$*" c
    printf '%s [%s] %s\n' "$(date '+%F %T')" "$lvl" "$msg" >>"$LOG_FILE" 2>/dev/null
    case $lvl in WARN) WARNINGS=$((WARNINGS + 1)) ;; ERR) ERRORS=$((ERRORS + 1)) ;; esac
    if (( GUI )) || [[ ! -t 1 ]]; then
        printf '[%s] %s\n' "$lvl" "$msg"
    else
        case $lvl in OK) c=32 ;; WARN) c=33 ;; ERR) c=31 ;; STEP) c=36 ;; SIM) c=35 ;; *) c=0 ;; esac
        printf '\e[%sm[%s]\e[0m %s\n' "$c" "$lvl" "$msg"
    fi
}
info() { _log INFO "$*"; }
ok()   { _log OK "$*"; }
warn() { _log WARN "$*"; }
err()  { _log ERR "$*"; }
step() { _log STEP "$*"; }
sim()  { _log SIM "$*"; }
die()  { err "$*"; exit 1; }

# comando che modifica il sistema: simulato con --dry-run, output nel log
run() {
    if (( DRY_RUN )); then sim "$(printf '%q ' "$@")"; return 0; fi
    local out rc
    out=$("$@" 2>&1); rc=$?
    [[ -n $out ]] && printf '%s\n' "$out" >>"$LOG_FILE" 2>/dev/null
    if (( rc != 0 )); then
        err "Comando fallito (codice $rc): $(printf '%q ' "$@")"
        [[ -n $out ]] && printf '%s\n' "$out" | head -n 4 | while IFS= read -r l; do _log ERR "  $l"; done
    fi
    return $rc
}

# come run, ma un fallimento e' solo informativo (unita' assenti, record gia' rimossi...)
run_quiet() {
    if (( DRY_RUN )); then sim "$(printf '%q ' "$@")"; return 0; fi
    local out rc
    out=$("$@" 2>&1); rc=$?
    [[ -n $out ]] && printf '%s\n' "$out" >>"$LOG_FILE" 2>/dev/null
    return $rc
}

# come run, ma nel log il comando e' mascherato (contiene segreti)
run_secret() {
    local label=$1; shift
    if (( DRY_RUN )); then sim "$label"; return 0; fi
    local out rc
    out=$("$@" 2>&1); rc=$?
    (( rc != 0 )) && err "Comando fallito (codice $rc): $label"
    return $rc
}

# mostra l'output di un comando di sola lettura
show() {
    local l
    "$@" 2>&1 | while IFS= read -r l; do _log INFO "  $l"; done
}

pause() { (( INTERACTIVE )) && { echo; read -r -p "Premi Invio per continuare..." _; }; return 0; }

# ------------------------------------------------------------------- utilita'
is_yes() { [[ ${1,,} =~ ^(yes|y|si|s|true|1|on)$ ]]; }
is_no()  { [[ ${1,,} =~ ^(no|n|false|0|off)$ ]]; }
trim()   { local s=$1; s=${s#"${s%%[![:space:]]*}"}; s=${s%"${s##*[![:space:]]}"}; printf '%s' "$s"; }
norm_list() { local s=${1//[,;]/ }; s=$(trim "$s"); printf '%s' "$s" | tr -s ' '; }
hsize() { [[ $1 =~ ^[0-9]+$ ]] && numfmt --to=iec --suffix=B "$1" 2>/dev/null || printf '%s' "${1:--}"; }

valid_name() { [[ $1 =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$ ]]; }
valid_user() { [[ $1 =~ ^[a-z_][a-z0-9_-]{0,31}$ ]]; }
valid_path() { [[ $1 =~ ^/[A-Za-z0-9/._-]+$ && $1 != *..* && $1 != / && $1 != */ ]]; }
valid_host() { [[ $1 =~ ^[A-Za-z0-9.:_-]+$ ]]; }
valid_iqn()  { [[ $1 =~ ^(iqn\.[0-9]{4}-[0-9]{2}\.|eui\.|naa\.)[[:graph:]]+$ && $1 != *\|* ]]; }

gen_password() { local p; p=$(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom 2>/dev/null | head -c 20); printf '%s' "$p"; }

backup_file() {
    [[ -f $1 ]] || return 0
    (( DRY_RUN )) && return 0
    local b; b="$1.bak-$(date +%Y%m%d-%H%M%S)"
    cp -a "$1" "$b" && info "Backup: $b"
}

# write_file <percorso> <modo se nuovo> <contenuto>: idempotente, backup, scrittura atomica
write_file() {
    local path=$1 mode=$2 content=$3 cur tmp
    if [[ -f $path ]]; then
        cur=$(cat "$path" 2>/dev/null)
        [[ $cur == "$content" ]] && { info "$path gia' corretto"; return 0; }
        mode=$(stat -c %a "$path" 2>/dev/null || echo "$mode")
    fi
    if (( DRY_RUN )); then
        sim "Scriverei $path:"
        printf '%s\n' "$content" | while IFS= read -r l; do _log SIM "    $l"; done
        return 0
    fi
    mkdir -p "$(dirname "$path")" || return 1
    backup_file "$path"
    tmp=$(mktemp "$path.XXXXXX") || return 1
    if printf '%s\n' "$content" >"$tmp" && chmod "$mode" "$tmp" && mv -f "$tmp" "$path"; then
        ok "Scritto $path"
    else
        rm -f "$tmp"; err "Scrittura di $path non riuscita"; return 1
    fi
}

load_config() {
    local f=$1 line key val n=0
    [[ $f == - ]] && f=/dev/stdin
    [[ -r $f ]] || die "File di configurazione non leggibile: $1"
    while IFS= read -r line || [[ -n $line ]]; do
        line=${line%$'\r'}
        [[ $line =~ ^[[:space:]]*(#|$) ]] && continue
        if [[ $line =~ ^[[:space:]]*([A-Z_]+)[[:space:]]*=(.*)$ ]]; then
            key=${BASH_REMATCH[1]}
            val=$(trim "${BASH_REMATCH[2]}")
            if [[ $val =~ ^\"(.*)\"$ || $val =~ ^\'(.*)\'$ ]]; then val=${BASH_REMATCH[1]}; fi
            if [[ " ${CONFIG_KEYS//$'\n'/ } " == *" $key "* ]]; then
                printf -v "CFG_$key" '%s' "$val"; n=$((n + 1))
            else
                warn "Chiave di configurazione sconosciuta ignorata: $key"
            fi
        else
            warn "Riga di configurazione ignorata: $line"
        fi
    done <"$f"
    info "Configurazione caricata ($n valori)"
}

save_config() {
    (( DRY_RUN )) && return 0
    local k v out
    out="# vrepo-setup $VERSION - configurazione salvata il $(date '+%F %T') (senza password)"
    for k in $CONFIG_KEYS; do
        [[ $SECRET_KEYS == *" $k "* ]] && continue
        v="CFG_$k"; out+=$'\n'"$k=\"${!v}\""
    done
    mkdir -p "$STATE_DIR" && printf '%s\n' "$out" >"$SAVED_CONF" && chmod 600 "$SAVED_CONF" && info "Configurazione salvata in $SAVED_CONF"
}

validate_config() {
    local bad=0 p
    [[ -z $CFG_INITIATOR_NAME ]] || valid_iqn "$CFG_INITIATOR_NAME" || { err "INITIATOR_NAME non valido: $CFG_INITIATOR_NAME"; bad=1; }
    for p in $(norm_list "$CFG_ISCSI_PORTALS"); do valid_host "$p" || { err "Portale iSCSI non valido: $p"; bad=1; }; done
    [[ $CFG_ISCSI_PORT =~ ^[0-9]{1,5}$ ]] || { err "ISCSI_PORT non valido"; bad=1; }
    valid_user "$CFG_VEEAM_USER" || { err "VEEAM_USER non valido: $CFG_VEEAM_USER"; bad=1; }
    valid_path "$CFG_MOUNT_BASE" || { err "MOUNT_BASE non valido: $CFG_MOUNT_BASE"; bad=1; }
    [[ $CFG_LUN_PREFIX =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,28}$ ]] || { err "LUN_PREFIX non valido"; bad=1; }
    [[ $CFG_MULTIPATH =~ ^(auto|yes|no|si)$ ]] || { err "MULTIPATH deve essere auto, yes o no"; bad=1; }
    [[ $CFG_MULTIPATH_PROFILE =~ ^(qnap|generic)$ ]] || { err "MULTIPATH_PROFILE deve essere qnap o generic"; bad=1; }
    [[ -z $CFG_TIMEZONE || $CFG_TIMEZONE =~ ^[A-Za-z0-9/_+-]+$ ]] || { err "TIMEZONE non valido"; bad=1; }
    for p in $(norm_list "$CFG_NTP_SERVERS"); do valid_host "$p" || { err "Server NTP non valido: $p"; bad=1; }; done
    [[ -z $CFG_ADMIN_USER ]] || valid_user "$CFG_ADMIN_USER" || { err "ADMIN_USER non valido"; bad=1; }
    [[ $CFG_CHAP_USER$CFG_CHAP_PASSWORD != *$'\n'* ]] || bad=1
    return $bad
}

require_root() { [[ $EUID -eq 0 ]] || die "Servono i privilegi di root: sudo $0 $*"; }

os_info() { (. /etc/os-release 2>/dev/null; printf '%s|%s|%s' "${ID:-?}" "${VERSION_ID:-?}" "${PRETTY_NAME:-?}"); }

check_os() {
    local id ver pretty
    IFS='|' read -r id ver pretty <<<"$(os_info)"
    if [[ $id != ubuntu ]]; then warn "Sistema $pretty: lo script e' pensato per Ubuntu"
    else case $ver in 20.04|22.04|24.04|26.04) info "Sistema: $pretty" ;; *) warn "Sistema $pretty: versione non verificata, controllare la compatibilita' Veeam" ;; esac
    fi
}

pkg_installed() { dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q 'install ok installed'; }

ensure_pkgs() {
    local missing=() p
    for p in "$@"; do pkg_installed "$p" || missing+=("$p"); done
    if (( ${#missing[@]} == 0 )); then info "Pacchetti presenti: $*"; return 0; fi
    info "Installo: ${missing[*]}"
    run env DEBIAN_FRONTEND=noninteractive apt-get update -q || warn "apt-get update non riuscito: provo comunque l'installazione"
    run env DEBIAN_FRONTEND=noninteractive apt-get install -y -q "${missing[@]}" || { err "Installazione di ${missing[*]} non riuscita"; return 1; }
    ok "Installati: ${missing[*]}"
}

# ------------------------------------------------------------------- whiptail
wt()    { whiptail --backtitle "$BT" "$@" 3>&1 1>&2 2>&3; }
ask()   { wt --title "$1" --inputbox "$2" 14 78 "$3"; }
askpw() { wt --title "$1" --passwordbox "$2" 12 78; }
yesno() { whiptail --backtitle "$BT" --title "$1" --yesno "$2" 18 78; }
noyes() { whiptail --backtitle "$BT" --title "$1" --defaultno --yesno "$2" 18 78; }
msg()   { whiptail --backtitle "$BT" --title "$1" --scrolltext --msgbox "$2" 22 78; }

# ------------------------------------------------------------------- stato
state_lookup()      { [[ -f $STATE_REPOS ]] && awk -F'|' -v c="$1" -v v="$2" '$c==v{print; exit}' "$STATE_REPOS"; return 0; }
state_add_repo() {
    mkdir -p "$STATE_DIR"
    local tmp; tmp=$(mktemp)
    [[ -f $STATE_REPOS ]] && awk -F'|' -v n="$1" '$1!=n' "$STATE_REPOS" >"$tmp"
    printf '%s|%s|%s|%s\n' "$1" "$2" "$3" "$4" >>"$tmp"
    mv -f "$tmp" "$STATE_REPOS" && chmod 644 "$STATE_REPOS"
}
repo_mounts() { [[ -f $STATE_REPOS ]] && awk -F'|' '{print $4}' "$STATE_REPOS"; return 0; }

# ------------------------------------------------------------------- dischi
# dischi che ospitano /, /boot, /boot/efi e lo swap: mai proposti
system_disks() {
    local src m
    {
        for m in / /boot /boot/efi; do findmnt -no SOURCE "$m" 2>/dev/null; done
        swapon --noheadings --show=NAME 2>/dev/null
    } | sed 's/\[.*//' | sort -u | while read -r src; do
        [[ -b $src ]] || continue
        lsblk -nslpo NAME,TYPE "$src" 2>/dev/null | awk '$2=="disk"||$2=="mpath"{print $1}'
    done | sort -u
}

dev_wwid() {
    local d=$1 k u
    k=$(basename "$(readlink -f "$d")")
    if [[ -r /sys/block/$k/dm/uuid ]]; then
        u=$(<"/sys/block/$k/dm/uuid")
        [[ $u == mpath-* ]] && { printf '%s' "${u#mpath-}"; return; }
    fi
    udevadm info --query=property --name="$d" 2>/dev/null | sed -n 's/^ID_SERIAL=//p' | head -n 1
}

# numero di LUN viste su piu' percorsi (stesso WWID su piu' dischi sd)
detect_multi_paths() {
    local d
    lsblk -dnpo NAME,TYPE 2>/dev/null | awk '$2=="disk"{print $1}' | while read -r d; do dev_wwid "$d"; echo; done \
        | awk 'NF' | sort | uniq -d | wc -l
}

# LUNS[]: dev|kname|wwid|byte|modello|percorsi|trasporto|stato|fstype|mount|nome
add_lun() {
    local dev=$1 k=$2 wwid=$3 paths=$4 tran=$5 model=$6
    local size fstype mnt children state="libero" name="-" rec
    size=$(lsblk -dnbo SIZE "$dev" 2>/dev/null | xargs)
    [[ -z $model ]] && model=$(lsblk -dno VENDOR,MODEL "$dev" 2>/dev/null | xargs)
    fstype=$(lsblk -dno FSTYPE "$dev" 2>/dev/null | xargs)
    [[ -z $fstype ]] && fstype=$(blkid -p -s TYPE -o value "$dev" 2>/dev/null || blkid -p -s PTTYPE -o value "$dev" 2>/dev/null)
    children=$(lsblk -nlpo NAME "$dev" 2>/dev/null | tail -n +2 | wc -l)
    mnt=$(lsblk -nlpo MOUNTPOINT "$dev" 2>/dev/null | awk 'NF' | head -n 1)
    rec=""
    [[ -n $wwid ]] && rec=$(state_lookup 2 "$wwid")
    if [[ -z $rec ]]; then # anche per UUID del filesystem (WWID cambiato o assente)
        local fu pd
        for pd in $(lsblk -nlpo NAME "$dev" 2>/dev/null); do
            fu=$(blkid -s UUID -o value "$pd" 2>/dev/null)
            [[ -n $fu ]] && rec=$(state_lookup 3 "$fu") && [[ -n $rec ]] && break
        done
    fi
    if [[ -n $rec ]]; then
        state="configurato"; name=${rec%%|*}
    elif [[ -n $fstype || $children -gt 0 || -n $mnt ]]; then
        state="in_uso"
    elif compgen -G "/sys/block/$k/holders/*" >/dev/null; then
        state="in_uso"
    elif [[ -n $(blkid -p -o export "$dev" 2>/dev/null) ]]; then
        state="in_uso"
    fi
    [[ -z $fstype && $children -gt 0 ]] && fstype=$(lsblk -nlpo FSTYPE "$dev" 2>/dev/null | awk 'NF' | head -n 1)
    model=${model//|/ }
    LUNS+=("$dev|$k|${wwid:--}|${size:-0}|${model:--}|$paths|${tran:--}|$state|${fstype:--}|${mnt:--}|$name")
}

scan_luns() {
    LUNS=()
    local sysd d k u name dev s n tran model
    sysd=" $(system_disks | tr '\n' ' ') "
    declare -A slave=()
    for d in /sys/block/dm-*; do
        [[ -r $d/dm/uuid ]] || continue
        u=$(<"$d/dm/uuid"); [[ $u == mpath-* ]] || continue
        k=${d##*/}; name=$(<"$d/dm/name"); dev=/dev/mapper/$name
        n=0; tran=""; model=""
        for s in "$d"/slaves/*; do
            [[ -e $s ]] || continue
            slave[${s##*/}]=1; n=$((n + 1))
            [[ -z $tran ]] && tran=$(lsblk -dno TRAN "/dev/${s##*/}" 2>/dev/null | xargs)
            [[ -z $model ]] && model=$(lsblk -dno VENDOR,MODEL "/dev/${s##*/}" 2>/dev/null | xargs)
        done
        [[ $sysd == *" $dev "* || $sysd == *" /dev/$k "* ]] && continue
        add_lun "$dev" "$k" "${u#mpath-}" "$n" "${tran:-mpath}" "$model"
    done
    while read -r dev type tran; do
        # VREPO_TEST_LOOP=1: include i loop device (solo per i test)
        [[ $type == disk || ( $type == loop && ${VREPO_TEST_LOOP:-} == 1 ) ]] || continue
        k=${dev##*/}
        [[ -n ${slave[$k]:-} ]] && continue
        [[ $sysd == *" $dev "* ]] && continue
        case $k in sr*|fd*|zram*|ram*|nbd*) continue ;; esac
        add_lun "$dev" "$k" "$(dev_wwid "$dev")" 1 "$tran" ""
    done < <(lsblk -dnpo NAME,TYPE,TRAN 2>/dev/null)
}

find_lun() { # per dispositivo, kname o wwid
    local q=$1 r
    for r in "${LUNS[@]}"; do
        IFS='|' read -r d k w _ <<<"$r"
        [[ $q == "$d" || $q == "$k" || $q == "/dev/$k" || $q == "$w" ]] && { printf '%s' "$r"; return 0; }
    done
    return 1
}

lun_label() { # testo leggibile per elenchi e checklist
    local d k w sz mo p t st fs mnt nm
    IFS='|' read -r d k w sz mo p t st fs mnt nm <<<"$1"
    printf '%-22s %8s  %s perc.  %-6s %s' "$d" "$(hsize "$sz")" "$p" "$t" "${mo:0:20}"
    case $st in in_uso) if [[ $mnt != - ]]; then printf '  [IN USO: montato su %s]' "$mnt"; else printf '  [IN USO: %s]' "$fs"; fi ;; configurato) printf '  [repo %s]' "$nm" ;; esac
}

configured_name_for() { # nome dalla mappa LUN_NAMES (wwid=nome o kname=nome)
    local w=$1 k=$2 e
    for e in $(norm_list "$CFG_LUN_NAMES"); do
        [[ $e == *=* ]] || continue
        [[ ${e%%=*} == "$w" || ${e%%=*} == "$k" || ${e%%=*} == "/dev/$k" ]] && { printf '%s' "${e#*=}"; return 0; }
    done
    return 1
}

suggest_name() { # nome libero <prefisso>NN
    local i=1 n
    while :; do
        printf -v n '%s%02d' "$CFG_LUN_PREFIX" "$i"
        if [[ -z $(state_lookup 1 "$n") && ! -e $CFG_MOUNT_BASE/$n && " ${RESERVED_NAMES:-} " != *" $n "* ]]; then printf '%s' "$n"; return; fi
        i=$((i + 1))
    done
}

find_partition() {
    local t=$1 p i
    for i in 1 2 3 4 5 6; do
        p=$(lsblk -lnpo NAME,TYPE "$t" 2>/dev/null | awk '$2=="part"{print $1; exit}')
        [[ -n $p && -b $p ]] && { printf '%s' "$p"; return 0; }
        for p in "$t-part1" "${t}p1" "${t}1"; do [[ -b $p ]] && { printf '%s' "$p"; return 0; }; done
        sleep 1; udevadm settle 2>/dev/null
    done
    return 1
}

# ------------------------------------------------------------------- iSCSI
iscsi_sessions() { # portale iqn per ogni sessione attiva
    iscsiadm -m session 2>/dev/null | awk '{p=$3; sub(/,.*/,"",p); print p, $4}'
}
session_count() { iscsi_sessions | awk 'NF' | wc -l; }

portal_ip() { local p=${1%:*}; p=${p#[}; p=${p%]}; printf '%s' "$p"; }

target_wanted() {
    local iqn=$1 pat list
    list=$(norm_list "$CFG_ISCSI_TARGETS")
    [[ -z $list ]] && return 0
    for pat in $list; do
        # shellcheck disable=SC2053
        [[ $iqn == $pat ]] && return 0
    done
    return 1
}
portal_wanted() {
    local ip p
    is_yes "$CFG_ONLY_LISTED_PORTALS" || return 0
    ip=$(portal_ip "$1")
    for p in $(norm_list "$CFG_ISCSI_PORTALS"); do [[ $p == "$ip" ]] && return 0; done
    return 1
}

# DISC[]: "portale iqn" dalla discovery sui portali indicati
discover_targets() {
    local nonpersist=$1 p out rc line portal iqn
    DISC=()
    for p in $(norm_list "$CFG_ISCSI_PORTALS"); do
        if [[ $nonpersist == 1 ]]; then out=$(iscsiadm -m discovery -t st -p "$p:$CFG_ISCSI_PORT" -o nonpersistent 2>&1); rc=$?
        else out=$(iscsiadm -m discovery -t st -p "$p:$CFG_ISCSI_PORT" 2>&1); rc=$?; fi
        if (( rc != 0 )); then warn "Discovery su $p:$CFG_ISCSI_PORT non riuscita: $(tail -n 1 <<<"$out")"; continue; fi
        while read -r portal iqn; do
            [[ -n $iqn ]] || continue
            portal=${portal%%,*}
            [[ " ${DISC[*]} " == *" $portal $iqn "* ]] || DISC+=("$portal $iqn")
        done <<<"$out"
    done
}

# ------------------------------------------------------------------- multipath
mp_profile() { [[ -s $STATE_MPPROFILE ]] && cat "$STATE_MPPROFILE" || printf '%s' "$CFG_MULTIPATH_PROFILE"; }

multipath_conf_content() {
    local prof=${1:-$(mp_profile)} w a
    printf '%s (profilo %s): le modifiche manuali vengono sovrascritte\n' "$MP_MARK" "$prof"
    if [[ $prof == qnap ]]; then
        cat <<'EOF'
defaults {
    user_friendly_names yes
    find_multipaths yes
    polling_interval 10
    path_selector "round-robin 0"
    path_grouping_policy multibus
    uid_attribute ID_SERIAL
    prio alua
    path_checker readsector0
    rr_min_io 100
    max_fds 8192
    rr_weight priorities
    failback immediate
    no_path_retry fail
}
EOF
    else
        cat <<'EOF'
defaults {
    user_friendly_names yes
    find_multipaths yes
}
EOF
    fi
    if [[ -s $STATE_ALIASES ]]; then
        echo "multipaths {"
        while IFS='|' read -r w a; do
            [[ -n $w && -n $a ]] && printf '    multipath {\n        wwid %s\n        alias %s\n    }\n' "$w" "$a"
        done <"$STATE_ALIASES"
        echo "}"
    fi
}

multipath_check_conf() {
    (( DRY_RUN )) && return 0
    local w
    w=$(multipath -t 2>&1 >/dev/null | grep -iE 'invalid|unknown|deprecat|ignor|error' | sort -u)
    if [[ -n $w ]]; then
        warn "multipath segnala problemi nella configurazione:"
        while IFS= read -r l; do warn "  $l"; done <<<"$w"
    fi
}

set_mpath_alias() {
    local wwid=$1 alias=$2 i tmp
    if (( DRY_RUN )); then sim "Alias multipath $alias per WWID $wwid (multipaths in /etc/multipath.conf)"; return 0; fi
    mkdir -p "$STATE_DIR"; tmp=$(mktemp)
    [[ -f $STATE_ALIASES ]] && awk -F'|' -v w="$wwid" -v a="$alias" '$1!=w && $2!=a' "$STATE_ALIASES" >"$tmp"
    printf '%s|%s\n' "$wwid" "$alias" >>"$tmp"; mv -f "$tmp" "$STATE_ALIASES"
    write_file /etc/multipath.conf 0644 "$(multipath_conf_content)" || return 1
    run_quiet multipathd reconfigure || run systemctl reload multipathd || return 1
    for i in $(seq 1 15); do [[ -b /dev/mapper/$alias ]] && { ok "Alias multipath attivo: /dev/mapper/$alias"; return 0; }; sleep 1; done
    err "Alias /dev/mapper/$alias non comparso"; return 1
}

# ------------------------------------------------------------------- utente e permessi
user_has_password() { [[ $(passwd -S "$1" 2>/dev/null | awk '{print $2}') == P ]]; }
user_in_sudo() { id -nG "$1" 2>/dev/null | tr ' ' '\n' | grep -qx sudo; }

apply_repo_perms() {
    local mp=$1 u=$CFG_VEEAM_USER
    if ! id "$u" >/dev/null 2>&1; then
        if (( DRY_RUN )); then sim "chown $u:$u $mp; chmod 700 $mp"; else info "Utente $u non ancora creato: i permessi su $mp vengono applicati nel passo Utente"; fi
        return 0
    fi
    run chown "$u:$u" "$mp" && run chmod 700 "$mp" && ok "Permessi su $mp: $u, 700"
}

protect_mountpoint() {
    local mp=$1
    mountpoint -q "$mp" 2>/dev/null && return 0
    if (( DRY_RUN )); then sim "chmod 000 + chattr +i $mp (se la LUN non e' montata nessuno scrive sul disco di sistema)"; return 0; fi
    chown root:root "$mp" && chmod 000 "$mp"
    if chattr +i "$mp" 2>/dev/null; then ok "Punto di mount protetto (immutabile quando la LUN non e' montata): $mp"
    else warn "chattr non supportato sul filesystem di sistema: $mp non protetto"; fi
}

veeam_hint() {
    local mps ips
    mps=$(repo_mounts | tr '\n' ' ')
    ips=$(hostname -I 2>/dev/null | xargs)
    cat <<EOF
Prossimi passi in Veeam Backup & Replication:
 1. Backup Infrastructure > Managed Servers > Add Server > Linux
    host: $(hostname) (${ips:-IP del server})
    credenziali: "Single-use credentials for hardened repository",
    utente $CFG_VEEAM_USER con la sua password (elevazione con sudo)
 2. Backup Repositories > Add > Direct attached storage > Linux (Hardened Repository)
    percorso: ${mps:-<punto di mount della LUN>}
    "Use fast cloning on XFS volumes" e immutabilita' (giorni)
 3. Poi sul server:  sudo $INSTALL_PATH lockdown
    (toglie il sudo all'utente Veeam, blocca la password, disattiva SSH)
EOF
}

# ============================================================================ PASSI
step_packages() {
    step "Prerequisiti e pacchetti"
    check_os
    local pk=(open-iscsi xfsprogs parted)
    is_no "$CFG_MULTIPATH" || pk+=(multipath-tools)
    ensure_pkgs "${pk[@]}"
}

step_ntp() {
    step "Ora di sistema (l'immutabilita' dipende da un orologio corretto)"
    local servers synced
    servers=$(norm_list "$CFG_NTP_SERVERS")
    if [[ -n $CFG_TIMEZONE ]]; then run timedatectl set-timezone "$CFG_TIMEZONE" && ok "Fuso orario: $CFG_TIMEZONE"; fi
    if [[ -n $servers ]]; then
        if systemctl is-active -q chrony 2>/dev/null; then
            warn "chrony attivo: i server NTP vanno configurati in /etc/chrony/chrony.conf (non modifico)"
        else
            write_file /etc/systemd/timesyncd.conf.d/vrepo-setup.conf 0644 "[Time]
NTP=$servers" && run systemctl restart systemd-timesyncd
        fi
    fi
    run timedatectl set-ntp true
    (( DRY_RUN )) && return 0
    sleep 2
    synced=$(timedatectl show -p NTPSynchronized --value 2>/dev/null)
    if [[ $synced == yes ]]; then ok "Orologio sincronizzato: $(date '+%F %T %Z')"
    else warn "Orologio non ancora sincronizzato via NTP ($(date '+%F %T %Z')): verificare che il server raggiunga un NTP"; fi
}

step_initiator() {
    step "Initiator iSCSI e avvio automatico"
    ensure_pkgs open-iscsi || return 1
    local f=/etc/iscsi/initiatorname.iscsi c=/etc/iscsi/iscsid.conf cur new changed=0
    cur=$(sed -n 's/^InitiatorName=//p' "$f" 2>/dev/null | head -n 1)
    if [[ -n $CFG_INITIATOR_NAME && $CFG_INITIATOR_NAME != "$cur" ]]; then
        valid_iqn "$CFG_INITIATOR_NAME" || { err "InitiatorName non valido: $CFG_INITIATOR_NAME"; return 1; }
        (( $(session_count) > 0 )) && warn "Ci sono sessioni iSCSI attive: il nuovo InitiatorName vale dal prossimo login"
        write_file "$f" 0600 "InitiatorName=$CFG_INITIATOR_NAME" || return 1
        cur=$CFG_INITIATOR_NAME; changed=1
    fi
    ok "InitiatorName: $cur  (da autorizzare sul target, es. QNAP > iSCSI > criteri di accesso)"
    if [[ -f $c ]]; then
        if grep -qE '^[[:space:]]*node\.startup[[:space:]]*=[[:space:]]*automatic' "$c" && ! grep -qE '^[[:space:]]*node\.startup[[:space:]]*=[[:space:]]*manual' "$c"; then
            info "node.startup = automatic gia' impostato"
        else
            new=$(sed -E 's/^[[:space:]]*#?[[:space:]]*node\.startup[[:space:]]*=.*/node.startup = automatic/' "$c")
            new=$(awk '/^node\.startup = automatic$/{if(seen++)next}1' <<<"$new")
            write_file "$c" 0600 "$new" || return 1
            changed=1
        fi
    else
        err "$c non trovato: open-iscsi installato correttamente?"; return 1
    fi
    run_quiet systemctl enable iscsid.service open-iscsi.service || run systemctl enable open-iscsi.service
    if (( changed )); then
        run systemctl restart iscsid
        if (( $(session_count) == 0 )); then run systemctl restart open-iscsi; else info "open-iscsi non riavviato: sessioni attive"; fi
    fi
    ok "Initiator pronto"
}

step_targets() {
    step "Connessione ai target iSCSI"
    ensure_pkgs open-iscsi || return 1
    [[ -n $(norm_list "$CFG_ISCSI_PORTALS") ]] || { err "Nessun portale iSCSI indicato (ISCSI_PORTALS)"; return 1; }
    discover_targets "$DRY_RUN"
    if (( ${#DISC[@]} == 0 )); then err "Nessun target scoperto: controllare IP, rete iSCSI e criteri di accesso sul NAS (InitiatorName)"; return 1; fi
    local e portal iqn sel=() items=() chosen active
    active=$(iscsi_sessions)
    for e in "${DISC[@]}"; do
        read -r portal iqn <<<"$e"
        if target_wanted "$iqn" && portal_wanted "$portal"; then items+=("$e" "ON"); else items+=("$e" "OFF"); fi
    done
    if (( INTERACTIVE )); then
        local args=() i
        for ((i = 0; i < ${#items[@]}; i += 2)); do args+=("${items[i]}" "" "${items[i+1]}"); done
        chosen=$(wt --title "Target scoperti" --separate-output --checklist \
            "Spunta portale e target su cui fare login (uno per percorso).\nI record non scelti vengono eliminati, cosi' al riavvio non si collega altro." \
            22 100 12 "${args[@]}") || return 1
        while IFS= read -r e; do [[ -n $e ]] && sel+=("$e"); done <<<"$chosen"
    else
        for ((i = 0; i < ${#items[@]}; i += 2)); do [[ ${items[i+1]} == ON ]] && sel+=("${items[i]}"); done
    fi
    (( ${#sel[@]} )) || { err "Nessun target selezionato (ISCSI_TARGETS / ONLY_LISTED_PORTALS)"; return 1; }
    local n_ok=0
    for e in "${DISC[@]}"; do
        read -r portal iqn <<<"$e"
        if [[ " ${sel[*]} " != *" $e "* ]]; then
            if grep -qxF "$portal $iqn" <<<"$active"; then info "Non selezionato ma connesso, lo lascio: $iqn @ $portal"
            else run_quiet iscsiadm -m node -T "$iqn" -p "$portal" -o delete && info "Record non usato eliminato: $iqn @ $portal"; fi
            continue
        fi
        info "Target $iqn @ $portal"
        run iscsiadm -m node -T "$iqn" -p "$portal" -o update -n node.startup -v automatic || continue
        run iscsiadm -m node -T "$iqn" -p "$portal" -o update -n 'node.conn[0].startup' -v automatic
        if [[ -n $CFG_CHAP_USER ]]; then
            run iscsiadm -m node -T "$iqn" -p "$portal" -o update -n node.session.auth.authmethod -v CHAP
            run iscsiadm -m node -T "$iqn" -p "$portal" -o update -n node.session.auth.username -v "$CFG_CHAP_USER"
            run_secret "iscsiadm ... node.session.auth.password = (nascosta)" iscsiadm -m node -T "$iqn" -p "$portal" -o update -n node.session.auth.password -v "$CFG_CHAP_PASSWORD"
        fi
        if grep -qxF "$portal $iqn" <<<"$active"; then ok "Gia' connesso: $iqn @ $portal"; n_ok=$((n_ok + 1)); continue; fi
        if (( DRY_RUN )); then sim "iscsiadm -m node -T $iqn -p $portal --login"; n_ok=$((n_ok + 1)); continue; fi
        local out rc
        out=$(iscsiadm -m node -T "$iqn" -p "$portal" --login 2>&1); rc=$?
        if (( rc == 0 || rc == 15 )); then ok "Login: $iqn @ $portal"; n_ok=$((n_ok + 1))
        else err "Login non riuscito su $iqn @ $portal: $(tail -n 1 <<<"$out")"; fi
    done
    run_quiet iscsiadm -m session --rescan
    (( DRY_RUN )) || { udevadm settle 2>/dev/null; sleep 2; }
    (( n_ok )) || { err "Nessun login riuscito"; return 1; }
    ok "Sessioni attive: $(session_count)"
    (( DRY_RUN )) || show iscsiadm -m session
    local mpd; mpd=$(detect_multi_paths)
    (( mpd > 0 )) && info "Rilevate $mpd LUN visibili su piu' percorsi: serve il multipath"
    return 0
}

step_multipath() {
    step "Multipath"
    local want=$CFG_MULTIPATH npaths
    if [[ $want == auto ]]; then
        npaths=$(detect_multi_paths)
        if (( npaths > 0 )) || [[ $(wc -w <<<"$(norm_list "$CFG_ISCSI_PORTALS")") -gt 1 ]]; then want=yes; else want=no; fi
        info "Multipath automatico: $want (LUN con piu' percorsi: $npaths)"
    fi
    if ! is_yes "$want"; then info "Multipath non richiesto: salto"; return 0; fi
    ensure_pkgs multipath-tools || return 1
    if (( ! DRY_RUN )); then mkdir -p "$STATE_DIR"; printf '%s' "$CFG_MULTIPATH_PROFILE" >"$STATE_MPPROFILE"; fi
    if [[ -f /etc/multipath.conf ]] && ! grep -qF "$MP_MARK" /etc/multipath.conf; then info "/etc/multipath.conf esistente non generato dal tool: viene salvato un backup"; fi
    write_file /etc/multipath.conf 0644 "$(multipath_conf_content "$CFG_MULTIPATH_PROFILE")" || return 1
    run_quiet systemctl enable multipathd.service
    run systemctl restart multipathd || return 1
    (( DRY_RUN )) && return 0
    sleep 3; multipath -r >/dev/null 2>&1; udevadm settle 2>/dev/null
    multipath_check_conf
    local maps; maps=$(multipath -l 2>/dev/null | grep -c 'dm-')
    if (( maps > 0 )); then ok "Dispositivi multipath: $maps"; show multipath -ll
    else warn "Nessun dispositivo multipath creato: le LUN hanno un solo percorso o il WWID non coincide"; fi
}

# configure_lun <dispositivo|wwid> <nome> <mount>
configure_lun() {
    local q=$1 name=$2 mp=$3 rec dev k wwid size model paths tran state fstype mnt cur
    valid_name "$name" || { err "Nome LUN non valido: '$name' (lettere, numeri, . _ -, max 32)"; return 1; }
    [[ -n $mp ]] || mp=$CFG_MOUNT_BASE/$name
    valid_path "$mp" || { err "Punto di mount non valido: $mp"; return 1; }
    scan_luns
    rec=$(find_lun "$q") || { err "$q non trovato tra i dischi utilizzabili (i dischi di sistema sono esclusi)"; return 1; }
    IFS='|' read -r dev k wwid size model paths tran state fstype mnt cur <<<"$rec"
    case $state in
        configurato)
            if [[ $cur == "$name" ]]; then ok "LUN $name gia' configurata ($dev)"; apply_repo_perms "$(state_lookup 1 "$name" | cut -d'|' -f4)"; return 0; fi
            err "$dev e' gia' il repository $cur"; return 1 ;;
        in_uso)
            [[ $mnt != - ]] && { err "$dev e' montato su $mnt: non lo tocco"; return 1; }
            compgen -G "/sys/block/$k/holders/*" >/dev/null && [[ $k != dm-* ]] && { err "$dev e' in uso (LVM/RAID/multipath): non lo tocco"; return 1; }
            is_yes "$CFG_FORCE_FORMAT" || { err "$dev contiene dati o partizioni ($fstype): per cancellarlo FORCE_FORMAT=yes"; return 1; }
            warn "FORCE_FORMAT: il contenuto di $dev ($fstype) viene cancellato" ;;
    esac
    [[ -n $(state_lookup 1 "$name") ]] && { err "Esiste gia' un repository con nome $name"; return 1; }
    mountpoint -q "$mp" 2>/dev/null && { err "$mp e' gia' un punto di mount"; return 1; }
    [[ -d $mp && -n $(ls -A "$mp" 2>/dev/null) ]] && { err "$mp non e' vuota"; return 1; }
    awk -v m="$mp" '$0 !~ /^[[:space:]]*#/ && $2==m {f=1} END{exit !f}' /etc/fstab && { err "$mp e' gia' in /etc/fstab"; return 1; }

    step "LUN $dev -> $name ($(hsize "$size"), $paths percorsi, $tran) su $mp"
    local target=$dev part uuid opts="defaults,nofail"
    if [[ $k == dm-* ]] && is_yes "$CFG_MULTIPATH_ALIAS" && [[ ${dev##*/} != "$name" ]] && [[ $wwid != - ]]; then
        set_mpath_alias "$wwid" "$name" || return 1
        (( DRY_RUN )) || target=/dev/mapper/$name
    fi
    [[ $tran == iscsi ]] && opts="defaults,_netdev,nofail"
    run wipefs -a "$target" || return 1
    part=$target
    if is_yes "$CFG_PARTITION"; then
        run parted -s "$target" mklabel gpt mkpart "$name" xfs 0% 100% || return 1
        if (( DRY_RUN )); then part="$target (partizione 1)"
        else
            udevadm settle 2>/dev/null
            [[ $k == dm-* ]] && { kpartx -u "$target" >/dev/null 2>&1; udevadm settle 2>/dev/null; }
            part=$(find_partition "$target") || { err "Partizione di $target non trovata"; return 1; }
            info "Partizione: $part"
        fi
    fi
    run mkfs.xfs -f -b size=4096 -m reflink=1,crc=1 -L "${name:0:12}" "$part" || return 1
    if (( DRY_RUN )); then uuid="<UUID>"
    else
        udevadm settle 2>/dev/null
        uuid=$(blkid -s UUID -o value "$part" 2>/dev/null)
        [[ -n $uuid ]] || { err "UUID di $part non letto"; return 1; }
        ok "XFS creato (reflink, crc, blocchi 4K), UUID $uuid"
    fi
    [[ -d $mp ]] || run mkdir -p "$mp" || return 1
    protect_mountpoint "$mp"
    local line="UUID=$uuid $mp xfs $opts 0 0"
    if (( DRY_RUN )); then sim "Aggiungerei a /etc/fstab: $line"
    elif ! grep -q "UUID=$uuid" /etc/fstab; then
        backup_file /etc/fstab
        printf '# vrepo-setup: LUN %s (wwid %s)\n%s\n' "$name" "$wwid" "$line" >>/etc/fstab || { err "Scrittura di /etc/fstab non riuscita"; return 1; }
        ok "fstab: $line"
        findmnt --verify --tab-file /etc/fstab >/dev/null 2>&1 || warn "findmnt --verify segnala avvisi su /etc/fstab: controllare"
    fi
    run_quiet systemctl daemon-reload
    run mount "$mp" || return 1
    if (( ! DRY_RUN )); then
        mountpoint -q "$mp" || { err "$mp non risulta montato"; return 1; }
        local xi; xi=$(xfs_info "$mp" 2>/dev/null)
        grep -q 'reflink=1' <<<"$xi" && ok "reflink attivo (Fast Clone)" || warn "reflink NON attivo su $mp"
        state_add_repo "$name" "$wwid" "$uuid" "$mp"
    fi
    apply_repo_perms "$mp"
    ok "Repository $name pronto su $mp$( ((DRY_RUN)) || printf " (%s)" "$(df -h --output=size "$mp" 2>/dev/null | tail -n 1 | xargs)")"
}

# tutte le LUN libere (modalita' non interattiva: serve --yes)
step_luns_auto() {
    step "Preparazione delle LUN libere"
    scan_luns
    local r d k w st n rc=0 any=0
    RESERVED_NAMES=""
    for r in "${LUNS[@]}"; do
        IFS='|' read -r d k w _ _ _ _ st _ <<<"$r"
        [[ $st == libero ]] || { info "Salto $(lun_label "$r")"; continue; }
        n=$(configured_name_for "$w" "$k") || n=$(suggest_name)
        RESERVED_NAMES+=" $n"
        any=1
        configure_lun "$d" "$n" "$CFG_MOUNT_BASE/$n" || rc=1
    done
    (( any )) || warn "Nessuna LUN libera trovata"
    return $rc
}

step_user() {
    step "Utente Veeam e permessi"
    local u=$CFG_VEEAM_USER pw=$CFG_VEEAM_PASSWORD gen=0 created=0 mp
    valid_user "$u" || { err "Nome utente non valido: $u"; return 1; }
    if id "$u" >/dev/null 2>&1; then info "Utente $u esistente"
    else run useradd -m -s /bin/bash "$u" || return 1; created=1; ok "Utente $u creato"; fi
    if [[ -z $pw ]] && { (( created )) || ! user_has_password "$u"; }; then pw=$(gen_password); gen=1; fi
    if [[ -n $pw ]]; then
        if (( DRY_RUN )); then sim "Imposterei la password di $u"
        else printf '%s:%s\n' "$u" "$pw" | chpasswd || { err "Password di $u non impostata"; return 1; }; passwd -u "$u" >/dev/null 2>&1; ok "Password di $u impostata"; fi
    else info "Password di $u invariata"; fi
    run usermod -aG sudo "$u" && ok "$u nel gruppo sudo (temporaneo: lo toglie la blindatura)"
    while read -r mp; do [[ -n $mp && -d $mp ]] && apply_repo_perms "$mp"; done < <(repo_mounts)
    if (( gen && ! DRY_RUN )); then
        ok "PASSWORD GENERATA per $u: $pw"
        info "Serve solo per aggiungere il server in VBR (credenziali single-use); la blindatura la blocca."
    fi
    while IFS= read -r l; do info "$l"; done <<<"$(veeam_hint)"
}

veeam_present() { [[ -d /opt/veeam ]] || systemctl list-unit-files 2>/dev/null | grep -qi '^veeam'; }

step_lockdown() {
    step "Blindatura (dopo l'aggiunta del repository in Veeam)"
    local u=$CFG_VEEAM_USER f
    if ! veeam_present; then
        if is_yes "$CFG_LOCKDOWN_FORCE"; then warn "Componenti Veeam non trovati: procedo perche' LOCKDOWN_FORCE=yes"
        elif (( INTERACTIVE )); then noyes "Blindatura" "Non trovo i componenti Veeam (/opt/veeam): il server non sembra ancora aggiunto a VBR.\n\nDopo la blindatura SSH e' spento e l'utente non ha piu' sudo.\n\nProcedere comunque?" || return 1
        else err "Componenti Veeam non trovati: aggiungere prima il server in VBR (o LOCKDOWN_FORCE=yes)"; return 1; fi
    else ok "Componenti Veeam presenti"; fi
    if id "$u" >/dev/null 2>&1; then
        if user_in_sudo "$u"; then run gpasswd -d "$u" sudo && ok "$u rimosso dal gruppo sudo"; else info "$u non e' nel gruppo sudo"; fi
        if (( ! DRY_RUN )) && sudo -l -U "$u" 2>/dev/null | grep -q 'may run'; then warn "$u ha ancora regole sudo (controllare /etc/sudoers e /etc/sudoers.d)"; fi
        if is_yes "$CFG_LOCK_VEEAM_PASSWORD"; then run passwd -l "$u" && ok "Password di $u bloccata (Veeam usa i certificati, non la password)"; fi
    else warn "Utente $u non trovato"; fi
    if [[ -f $SUDOERS_FILE ]]; then run rm -f "$SUDOERS_FILE" && ok "Rimossa la regola sudo del tool ($SUDOERS_FILE)"; fi
    for f in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; do
        [[ -f $f ]] && grep -q " $KEY_COMMENT\$" "$f" || continue
        run sed -i "/ $KEY_COMMENT\$/d" "$f" && ok "Rimossa la chiave SSH del tool da $f"
    done
    if is_yes "$CFG_SSH_DISABLE"; then
        ok "Disattivo SSH (riattivabile solo da console: sudo $INSTALL_PATH unlock)"
        run_quiet systemctl disable --now ssh.socket
        run_quiet systemctl disable --now ssh.service || run_quiet systemctl disable --now sshd.service
        if (( ! DRY_RUN )) && systemctl is-enabled -q ssh.service 2>/dev/null; then warn "ssh.service risulta ancora abilitato"; fi
    else info "SSH lasciato attivo (SSH_DISABLE=no)"; fi
    ok "Blindatura completata"
}

step_unlock() {
    step "Riapertura temporanea (aggiornamento componenti Veeam)"
    (( INTERACTIVE )) || { err "La riapertura si fa solo da console, in modo interattivo"; return 1; }
    local u=$CFG_VEEAM_USER pw
    id "$u" >/dev/null 2>&1 || { err "Utente $u non trovato"; return 1; }
    pw=$(askpw "Password temporanea" "Nuova password per $u (vuoto = generata)") || return 1
    [[ -z $pw ]] && pw=$(gen_password)
    if (( DRY_RUN )); then sim "Imposterei la password di $u"
    else printf '%s:%s\n' "$u" "$pw" | chpasswd && passwd -u "$u" >/dev/null 2>&1; fi
    run usermod -aG sudo "$u"
    run_quiet systemctl enable --now ssh.service || run systemctl enable --now ssh.socket
    ok "Riaperto: SSH attivo, $u nel gruppo sudo, password: $pw"
    info "In VBR: aggiornare i componenti con credenziali single-use; poi rieseguire: sudo $INSTALL_PATH lockdown"
}

step_remove_targets() {
    step "Disconnessione target iSCSI"
    local s=() e portal iqn chosen sel=() pats mnts
    while read -r portal iqn; do [[ -n $iqn ]] && s+=("$portal $iqn"); done < <(iscsi_sessions)
    (( ${#s[@]} )) || { info "Nessuna sessione iSCSI attiva"; return 0; }
    if (( INTERACTIVE )); then
        local args=()
        for e in "${s[@]}"; do args+=("$e" "" OFF); done
        chosen=$(wt --title "Disconnetti target" --separate-output --checklist "Sessioni da chiudere (logout ed eliminazione del nodo):" 20 100 10 "${args[@]}") || return 1
        while IFS= read -r e; do [[ -n $e ]] && sel+=("$e"); done <<<"$chosen"
    else
        pats=$(norm_list "${OPT_TARGET:-$CFG_REMOVE_TARGETS}")
        [[ -n $pats ]] || { err "Indicare i target da disconnettere (REMOVE_TARGETS o --target)"; return 1; }
        for e in "${s[@]}"; do
            read -r portal iqn <<<"$e"
            # shellcheck disable=SC2053
            for p in $pats; do [[ $iqn == $p ]] && { sel+=("$e"); break; }; done
        done
    fi
    (( ${#sel[@]} )) || { warn "Nessuna sessione corrisponde"; return 0; }
    local rc=0 sid dev
    for e in "${sel[@]}"; do
        read -r portal iqn <<<"$e"
        mnts=""
        for sid in /sys/class/iscsi_session/session*; do
            [[ $(cat "$sid/targetname" 2>/dev/null) == "$iqn" ]] || continue
            for dev in "$sid"/device/target*/*/block/*; do
                [[ -e $dev ]] && mnts+=$(lsblk -nlpo MOUNTPOINT "/dev/${dev##*/}" 2>/dev/null | awk 'NF' | tr '\n' ' ')
            done
        done
        if [[ -n $(trim "$mnts") ]]; then err "$iqn ha dischi montati ($mnts): smontarli e togliere le righe da /etc/fstab prima"; rc=1; continue; fi
        run iscsiadm -m node -T "$iqn" -p "$portal" -u && ok "Logout: $iqn @ $portal"
        run iscsiadm -m node -T "$iqn" -p "$portal" -o delete && ok "Nodo eliminato: $iqn @ $portal"
        if is_yes "$CFG_REMOVE_DISCOVERY"; then run_quiet iscsiadm -m discoverydb -t sendtargets -p "$portal" -o delete && info "Discovery eliminata: $portal"; fi
    done
    return $rc
}

step_install_access() {
    step "Installazione del tool e accesso per la GUI"
    local admin=${CFG_ADMIN_USER:-${SUDO_USER:-}} src
    src=$(readlink -f "$0")
    [[ -n $admin && $admin != root ]] || { err "Eseguire con sudo dall'utente amministratore (SUDO_USER non disponibile)"; return 1; }
    valid_user "$admin" || { err "Utente amministratore non valido: $admin"; return 1; }
    if [[ $src != "$INSTALL_PATH" ]]; then run install -o root -g root -m 0755 "$src" "$INSTALL_PATH" || return 1; ok "Script installato in $INSTALL_PATH"; fi
    local rule="$admin ALL=(root) NOPASSWD: $INSTALL_PATH"
    if (( DRY_RUN )); then sim "Regola sudo: $rule"; return 0; fi
    local tmp; tmp=$(mktemp)
    printf '# vrepo-setup: la GUI esegue solo questo script senza password. Rimossa dalla blindatura.\n%s\n' "$rule" >"$tmp"
    if visudo -cf "$tmp" >/dev/null 2>&1; then install -o root -g root -m 0440 "$tmp" "$SUDOERS_FILE" && ok "Regola sudo: $rule"
    else err "Regola sudo non valida, non installata"; rm -f "$tmp"; return 1; fi
    rm -f "$tmp"
}

step_status() {
    step "Stato del server $(hostname)"
    local id ver pretty r d k w sz mo p t st fs mnt nm u=$CFG_VEEAM_USER
    IFS='|' read -r id ver pretty <<<"$(os_info)"
    info "Sistema: $pretty, kernel $(uname -r), IP: $(hostname -I 2>/dev/null | xargs)"
    info "Ora: $(date '+%F %T %Z'), NTP sincronizzato: $(timedatectl show -p NTPSynchronized --value 2>/dev/null)"
    info "InitiatorName: $(sed -n 's/^InitiatorName=//p' /etc/iscsi/initiatorname.iscsi 2>/dev/null)"
    info "Sessioni iSCSI: $(session_count)"
    iscsi_sessions | while read -r p w; do [[ -n $w ]] && info "  $w @ $p"; done
    if systemctl is-active -q multipathd 2>/dev/null; then info "multipathd attivo, mappe: $(multipath -l 2>/dev/null | grep -c 'dm-')"; else info "multipathd non attivo"; fi
    scan_luns
    info "Dischi utilizzabili (esclusi quelli di sistema): ${#LUNS[@]}"
    for r in "${LUNS[@]}"; do info "  $(lun_label "$r")"; done
    if [[ -s $STATE_REPOS ]]; then
        while IFS='|' read -r nm w d mnt; do
            if mountpoint -q "$mnt" 2>/dev/null; then
                local own; own=$(stat -c '%U %a' "$mnt")
                local rf; rf=$(xfs_info "$mnt" 2>/dev/null | grep -o 'reflink=[01]')
                ok "Repository $nm su $mnt: $(df -h --output=size,avail "$mnt" | tail -n 1 | xargs), owner/permessi $own, $rf"
            else err "Repository $nm: $mnt NON montato"; fi
        done <"$STATE_REPOS"
    fi
    if id "$u" >/dev/null 2>&1; then
        local pst; pst=$(passwd -S "$u" 2>/dev/null | awk '{print $2}')
        info "Utente $u: sudo $(user_in_sudo "$u" && echo SI || echo no), password $( [[ $pst == L ]] && echo bloccata || echo attiva)"
    else info "Utente $u non presente"; fi
    info "Componenti Veeam: $(veeam_present && echo presenti || echo assenti)"
    info "SSH: $(systemctl is-active ssh.service 2>/dev/null) / socket $(systemctl is-active ssh.socket 2>/dev/null), regola sudo del tool: $([[ -f $SUDOERS_FILE ]] && echo presente || echo assente)"
}

# output a righe per la GUI: TIPO|campi...
step_scan() {
    local id ver pretty r d k w sz mo p t st fs mnt nm u=$CFG_VEEAM_USER
    IFS='|' read -r id ver pretty <<<"$(os_info)"
    echo "VER|$VERSION"
    echo "HOST|$(hostname)|$pretty|$(hostname -I 2>/dev/null | xargs)"
    echo "INITIATOR|$(sed -n 's/^InitiatorName=//p' /etc/iscsi/initiatorname.iscsi 2>/dev/null)"
    local pks=ok; for p in open-iscsi xfsprogs parted; do pkg_installed "$p" || pks=todo; done
    echo "STEP|PACKAGES|$pks|open-iscsi, xfsprogs, parted$(pkg_installed multipath-tools && echo ', multipath-tools')"
    local sy; sy=$(timedatectl show -p NTPSynchronized --value 2>/dev/null)
    echo "STEP|NTP|$([[ $sy == yes ]] && echo ok || echo todo)|NTP sincronizzato: ${sy:-?}, $(date '+%F %T %Z')"
    local ns=todo; grep -qE '^[[:space:]]*node\.startup[[:space:]]*=[[:space:]]*automatic' /etc/iscsi/iscsid.conf 2>/dev/null && ns=ok
    echo "STEP|INITIATOR|$ns|node.startup automatic: $ns"
    local sc; sc=$(session_count)
    echo "STEP|TARGETS|$( ((sc > 0)) && echo ok || echo todo)|sessioni attive: $sc"
    local mpc=todo; grep -qF "$MP_MARK" /etc/multipath.conf 2>/dev/null && systemctl is-active -q multipathd 2>/dev/null && mpc=ok
    echo "STEP|MULTIPATH|$mpc|multipath.conf del tool: $mpc, LUN con piu' percorsi: $(detect_multi_paths)"
    local us=todo; id "$u" >/dev/null 2>&1 && us=ok
    echo "STEP|USER|$us|utente $u: $us$(id "$u" >/dev/null 2>&1 && user_in_sudo "$u" && echo ', in sudo')"
    echo "STEP|LOCKDOWN|todo|componenti Veeam: $(veeam_present && echo presenti || echo assenti)"
    while read -r p w; do [[ -n $w ]] && echo "SESSION|$p|$w"; done < <(iscsi_sessions)
    if [[ -n $(norm_list "$CFG_ISCSI_PORTALS") ]]; then
        discover_targets 1 2>/dev/null
        for r in "${DISC[@]}"; do read -r p w <<<"$r"; echo "TARGET|$p|$w"; done
    fi
    scan_luns
    for r in "${LUNS[@]}"; do echo "LUN|$r"; done
    [[ -s $STATE_REPOS ]] && while IFS='|' read -r nm w d mnt; do echo "REPO|$nm|$w|$mnt|$(mountpoint -q "$mnt" 2>/dev/null && echo montato || echo smontato)"; done <"$STATE_REPOS"
    return 0
}

step_prepare() {
    local rc=0
    step_packages || return 1
    step_ntp
    step_initiator || return 1
    step_targets || return 1
    step_multipath || rc=1
    if (( ASSUME_YES )); then step_luns_auto || rc=1
    else info "LUN: nessuna formattata senza --yes (usare il comando 'lun' o 'luns --yes')"; fi
    step_user || rc=1
    return $rc
}

# ============================================================================ WIZARD
wizard_network() {
    local cur v
    cur=$(sed -n 's/^InitiatorName=//p' /etc/iscsi/initiatorname.iscsi 2>/dev/null)
    v=$(ask "Initiator iSCSI" "InitiatorName di questo server (va autorizzato sul NAS/target).\nLasciare quello proposto per non cambiarlo." "${CFG_INITIATOR_NAME:-$cur}") || return 1
    [[ $v == "$cur" ]] && v=""
    CFG_INITIATOR_NAME=$v
    v=$(ask "Portali iSCSI" "IP del target separati da spazio.\nCon multipath: un IP per ogni percorso (es. 10.10.1.10 10.10.2.10)." "$CFG_ISCSI_PORTALS") || return 1
    CFG_ISCSI_PORTALS=$(norm_list "$v")
    v=$(ask "Porta iSCSI" "Porta TCP del target" "$CFG_ISCSI_PORT") || return 1
    CFG_ISCSI_PORT=$v
    v=$(ask "Target" "IQN da usare, anche con * (es. iqn.2004-04.com.qnap:*veeam*).\nVuoto = scelgo dall'elenco scoperto." "$CFG_ISCSI_TARGETS") || return 1
    CFG_ISCSI_TARGETS=$v
    if noyes "CHAP" "Il target richiede autenticazione CHAP?"; then
        CFG_CHAP_USER=$(ask "CHAP" "Utente CHAP" "$CFG_CHAP_USER") || return 1
        CFG_CHAP_PASSWORD=$(askpw "CHAP" "Password CHAP (12-16 caratteri su QNAP)") || return 1
    else CFG_CHAP_USER=""; CFG_CHAP_PASSWORD=""; fi
    validate_config || { msg "Errore" "Valori non validi: vedere i messaggi nel terminale."; return 1; }
}

wizard_ntp() {
    local v
    v=$(ask "Ora di sistema" "Server NTP separati da spazio (vuoto = predefiniti di Ubuntu).\nCon l'immutabilita' l'orologio corretto e' essenziale." "$CFG_NTP_SERVERS") || return 1
    CFG_NTP_SERVERS=$v
    v=$(ask "Fuso orario" "Fuso orario (vuoto = non cambiare). Attuale: $(timedatectl show -p Timezone --value 2>/dev/null)" "$CFG_TIMEZONE") || return 1
    CFG_TIMEZONE=$v
}

wizard_multipath() {
    local n ch def=no
    n=$(detect_multi_paths)
    (( n > 0 )) && def=qnap
    ch=$(wt --title "Multipath" --default-item "$def" --menu "LUN viste su piu' percorsi: $n\nScegli la configurazione:" 16 78 4 \
        qnap "Profilo QNAP (round-robin, multibus, alua)" \
        generic "Profilo generico (impostazioni di default)" \
        no "Nessun multipath") || return 1
    if [[ $ch == no ]]; then CFG_MULTIPATH=no; else CFG_MULTIPATH=yes; CFG_MULTIPATH_PROFILE=$ch; fi
    if [[ $CFG_MULTIPATH == yes ]]; then
        if yesno "Alias" "Dare alle LUN multipath il nome del repository (/dev/mapper/<nome>) invece di mpatha, mpathb...?"; then CFG_MULTIPATH_ALIAS=yes; else CFG_MULTIPATH_ALIAS=no; fi
    fi
}

wizard_luns() {
    scan_luns
    if (( ${#LUNS[@]} == 0 )); then msg "LUN" "Nessun disco utilizzabile trovato (dischi di sistema esclusi).\nControllare login iSCSI e multipath."; return 1; fi
    local args=() r d k w st sel names=() mps=() devs=() force=() n m plan="" i v
    for r in "${LUNS[@]}"; do
        IFS='|' read -r d k w _ _ _ _ st _ <<<"$r"
        [[ $st == configurato ]] && continue
        args+=("$d" "$(lun_label "$r" | cut -c24-)" "$([[ $st == libero ]] && echo ON || echo OFF)")
    done
    (( ${#args[@]} )) || { msg "LUN" "Tutti i dischi sono gia' configurati come repository."; return 0; }
    sel=$(wt --title "LUN da preparare" --separate-output --checklist "Le LUN selezionate verranno PARTIZIONATE e FORMATTATE in XFS.\nQuelle IN USO contengono dati." 22 100 12 "${args[@]}") || return 1
    [[ -n $sel ]] || return 0
    v=$(ask "Punti di mount" "Cartella base dei punti di mount" "$CFG_MOUNT_BASE") || return 1
    CFG_MOUNT_BASE=$v
    RESERVED_NAMES=""
    while IFS= read -r d; do
        [[ -n $d ]] || continue
        r=$(find_lun "$d"); IFS='|' read -r d k w _ _ _ _ st _ <<<"$r"
        n=$(configured_name_for "$w" "$k") || n=$(suggest_name)
        n=$(ask "Nome LUN" "$(lun_label "$r")\n\nNome del repository (etichetta XFS, alias multipath, cartella):" "$n") || return 1
        valid_name "$n" || { msg "Errore" "Nome non valido: $n"; return 1; }
        RESERVED_NAMES+=" $n"
        m=$(ask "Punto di mount" "Punto di mount per $n" "$CFG_MOUNT_BASE/$n") || return 1
        if [[ $st == in_uso ]]; then
            noyes "ATTENZIONE" "$d contiene dati o partizioni.\n\n$(lun_label "$r")\n\nCancellare TUTTO il contenuto?" || continue
            force+=("yes")
        else force+=("no"); fi
        devs+=("$d"); names+=("$n"); mps+=("$m")
        plan+="$d -> $n su $m\n"
    done <<<"$sel"
    (( ${#devs[@]} )) || return 0
    v=$(ask "Conferma" "Verranno cancellate e formattate:\n\n$plan\nScrivi FORMATTA per procedere:" "") || return 1
    [[ $v == FORMATTA ]] || { msg "LUN" "Annullato: nessuna modifica."; return 1; }
    clear
    local savef=$CFG_FORCE_FORMAT
    for i in "${!devs[@]}"; do
        CFG_FORCE_FORMAT=${force[i]}
        configure_lun "${devs[i]}" "${names[i]}" "${mps[i]}"
    done
    CFG_FORCE_FORMAT=$savef
    pause
}

wizard_user() {
    local v pw pw2
    v=$(ask "Utente Veeam" "Utente locale usato da Veeam per il repository" "$CFG_VEEAM_USER") || return 1
    valid_user "$v" || { msg "Errore" "Nome utente non valido: $v"; return 1; }
    CFG_VEEAM_USER=$v
    pw=$(askpw "Password" "Password per $v (vuoto = generata, oppure invariata se esiste gia')") || return 1
    if [[ -n $pw ]]; then
        pw2=$(askpw "Password" "Ripeti la password") || return 1
        [[ $pw == "$pw2" ]] || { msg "Errore" "Le password non coincidono."; return 1; }
    fi
    CFG_VEEAM_PASSWORD=$pw
    clear; step_user; CFG_VEEAM_PASSWORD=""; pause
}

wizard_full() {
    local ips cur
    ips=$(hostname -I 2>/dev/null | xargs)
    cur=$(sed -n 's/^InitiatorName=//p' /etc/iscsi/initiatorname.iscsi 2>/dev/null)
    msg "Configurazione guidata" "Server: $(hostname)  ($ips)\nSistema: $(os_info | cut -d'|' -f3)\nInitiatorName: ${cur:-(open-iscsi non installato)}\n\nPassi:\n 1. pacchetti e ora di sistema\n 2. initiator e target iSCSI\n 3. multipath\n 4. LUN: GPT, XFS reflink, fstab, mount protetto\n 5. utente Veeam con sudo temporaneo\n\nDopo l'aggiunta in VBR: Blindatura dal menu.\nSimulazione: $( ((DRY_RUN)) && echo ATTIVA || echo no)" || return
    wizard_network || return
    wizard_ntp || return
    clear
    step_packages && step_ntp && step_initiator || { pause; return; }
    step_targets || { pause; return; }
    pause
    wizard_multipath || return
    clear; step_multipath; pause
    wizard_luns
    wizard_user || return
    save_config
    msg "Fatto" "$(veeam_hint)"
}

wizard_menu() {
    local ch
    while :; do
        ch=$(wt --title "Menu principale" --menu "Host $(hostname) - $(hostname -I 2>/dev/null | xargs)\nSimulazione: $( ((DRY_RUN)) && echo ATTIVA || echo no)" 24 80 14 \
            1 "Configurazione guidata completa" \
            2 "Pacchetti e ora di sistema (NTP)" \
            3 "Initiator iSCSI" \
            4 "Connessione ai target iSCSI" \
            5 "Multipath" \
            6 "Prepara LUN (GPT, XFS, fstab, mount)" \
            7 "Utente Veeam e permessi" \
            8 "Blindatura (dopo l'aggiunta in Veeam)" \
            9 "Riapri per aggiornamento Veeam (temporaneo)" \
            10 "Disconnetti target iSCSI" \
            11 "Stato e verifica" \
            12 "Simulazione on/off" \
            0 "Esci") || break
        case $ch in
            1) wizard_full ;;
            2) wizard_ntp && { clear; step_packages; step_ntp; pause; } ;;
            3) wizard_network && { clear; step_initiator; pause; } ;;
            4) { [[ -n $CFG_ISCSI_PORTALS ]] || wizard_network; } && { clear; step_targets; pause; } ;;
            5) wizard_multipath && { clear; step_multipath; pause; } ;;
            6) wizard_luns ;;
            7) wizard_user ;;
            8) clear; step_lockdown; pause ;;
            9) clear; step_unlock; pause ;;
            10) clear; step_remove_targets; pause ;;
            11) clear; step_status; pause ;;
            12) DRY_RUN=$((1 - DRY_RUN)) ;;
            0) break ;;
        esac
        save_config
    done
    clear
}

# ============================================================================ MAIN
usage() {
    cat <<EOF
vrepo-setup $VERSION - hardened repository Veeam su Ubuntu

Uso: sudo $0 [opzioni] [comando]

Comandi:
  wizard          menu interattivo (predefinito da terminale)
  prepare         pacchetti, NTP, initiator, target, multipath, utente (LUN solo con --yes)
  packages | ntp | initiator | targets | multipath | user    singoli passi
  lun             prepara una LUN: --dev /dev/sdX|--wwid W  --name NOME  [--mount PERCORSO]
  luns --yes      prepara tutte le LUN libere (nomi da LUN_NAMES o <prefisso>NN)
  lockdown        blindatura dopo l'aggiunta in VBR
  unlock          riapertura temporanea per aggiornare i componenti Veeam (solo console)
  remove-targets  logout ed eliminazione dei target (REMOVE_TARGETS o --target IQN)
  status          stato e verifica
  scan            stato in formato macchina (per la GUI)
  install-access  installa lo script in $INSTALL_PATH e la regola sudo per la GUI
  version

Opzioni:
  --config FILE   configurazione KEY=VALUE (- = standard input); predefinita $SAVED_CONF
  --dry-run       simulazione: mostra cosa farebbe senza modificare nulla
  --yes           conferma le azioni distruttive in modalita' non interattiva
  --gui           output semplice per la GUI, nessuna domanda

Log: $LOG_FILE
EOF
}

main() {
    local cmd="" a
    while (( $# )); do
        a=$1; shift
        case $a in
            --config) CONFIG_FILE=${1:-}; shift ;;
            --dry-run|--simulate) DRY_RUN=1 ;;
            --yes|-y) ASSUME_YES=1 ;;
            --gui) GUI=1 ;;
            --dev) OPT_DEV=${1:-}; shift ;;
            --wwid) OPT_WWID=${1:-}; shift ;;
            --name) OPT_NAME=${1:-}; shift ;;
            --mount) OPT_MOUNT=${1:-}; shift ;;
            --target) OPT_TARGET=${1:-}; shift ;;
            -h|--help|help) usage; exit 0 ;;
            version|--version) echo "$VERSION"; exit 0 ;;
            -*) echo "Opzione sconosciuta: $a" >&2; usage >&2; exit 2 ;;
            *) [[ -z $cmd ]] && cmd=$a || { echo "Comando in piu': $a" >&2; exit 2; } ;;
        esac
    done
    if [[ -z $cmd ]]; then
        if [[ -t 0 && -t 1 ]] && (( ! GUI )); then cmd=wizard; else usage; exit 2; fi
    fi
    require_root "$cmd"
    touch "$LOG_FILE" 2>/dev/null && chmod 600 "$LOG_FILE" 2>/dev/null
    local q=""; [[ $cmd == scan ]] && q=1
    if [[ -n $CONFIG_FILE ]]; then if [[ -n $q ]]; then load_config "$CONFIG_FILE" >/dev/null; else load_config "$CONFIG_FILE"; fi
    elif [[ -r $SAVED_CONF ]]; then load_config "$SAVED_CONF" >/dev/null; fi
    [[ $cmd == scan ]] || { validate_config || exit 2; }
    if [[ $cmd == wizard || $cmd == unlock ]]; then
        (( GUI )) && { err "Il comando $cmd richiede un terminale"; exit 2; }
        command -v whiptail >/dev/null 2>&1 || ensure_pkgs whiptail || die "whiptail non disponibile"
        INTERACTIVE=1
    fi
    [[ $cmd == scan ]] || info "vrepo-setup $VERSION - comando $cmd$( ((DRY_RUN)) && echo ' (SIMULAZIONE)')"
    local rc=0
    case $cmd in
        wizard) wizard_menu ;;
        prepare) step_prepare || rc=1 ;;
        packages) step_packages || rc=1 ;;
        ntp) step_ntp || rc=1 ;;
        initiator) step_initiator || rc=1 ;;
        targets) step_targets || rc=1 ;;
        multipath) step_multipath || rc=1 ;;
        lun)
            [[ -n ${OPT_DEV:-$OPT_WWID} ]] || die "Indicare --dev o --wwid"
            if [[ -z $OPT_NAME ]]; then scan_luns; r=$(find_lun "${OPT_DEV:-$OPT_WWID}") && IFS='|' read -r _ k w _ <<<"$r"; OPT_NAME=$(configured_name_for "${w:-}" "${k:-}") || OPT_NAME=$(suggest_name); fi
            configure_lun "${OPT_DEV:-$OPT_WWID}" "$OPT_NAME" "$OPT_MOUNT" || rc=1 ;;
        luns) (( ASSUME_YES )) || die "Il comando luns formatta i dischi: aggiungere --yes"; step_luns_auto || rc=1 ;;
        user) step_user || rc=1 ;;
        lockdown) step_lockdown || rc=1 ;;
        unlock) step_unlock || rc=1 ;;
        remove-targets) step_remove_targets || rc=1 ;;
        status) step_status ;;
        scan) step_scan; exit 0 ;;
        install-access) step_install_access || rc=1 ;;
        *) echo "Comando sconosciuto: $cmd" >&2; usage >&2; exit 2 ;;
    esac
    (( rc == 0 && ERRORS > 0 )) && rc=1
    if [[ $cmd != wizard ]]; then
        if (( rc == 0 )); then ok "Fine: $cmd completato ($WARNINGS avvisi)"; else err "Fine: $cmd terminato con errori ($ERRORS errori, $WARNINGS avvisi)"; fi
    fi
    exit $rc
}

main "$@"
