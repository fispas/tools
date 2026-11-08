"""Genera i tool single-file a partire dalla libreria comune _lib/toolkit e dalle parti di ogni tool.

Uso (dalla root del repo):  python _lib/build.py
Ogni file generato = head + core_pre + $Engine = { core_engine + engine... } + gui + core_main
I file generati sono UTF-8 con BOM e CRLF. Non vanno modificati a mano.
"""
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LIB = os.path.join(ROOT, '_lib', 'toolkit')
FSL = 'rds/fslogix/_migrator-src'

TOOLS = {
    'rds/fslogix/upd-to-fslogix/Convert-UPDToFSLogix.ps1':
        (f'{FSL}/upd_head.ps1', [f'{FSL}/fslogix_engine.ps1', f'{FSL}/upd_engine.ps1'], f'{FSL}/upd_gui.ps1'),
    'rds/fslogix/roaming-to-fslogix/Convert-RoamingProfileToFSLogix.ps1':
        (f'{FSL}/roaming_head.ps1', [f'{FSL}/fslogix_engine.ps1', f'{FSL}/roaming_engine.ps1'], f'{FSL}/roaming_gui.ps1'),
    'rds/fslogix/local-to-fslogix/Convert-LocalProfileToFSLogix.ps1':
        (f'{FSL}/local_head.ps1', [f'{FSL}/fslogix_engine.ps1', f'{FSL}/local_engine.ps1'], f'{FSL}/local_gui.ps1'),
    'active-directory/ad-hardening/Invoke-ADAssessment.ps1':
        ('active-directory/ad-hardening/_src/head.ps1', ['active-directory/ad-hardening/_src/engine.ps1', 'active-directory/ad-hardening/_src/hardening.ps1', 'active-directory/ad-hardening/_src/extra.ps1'], 'active-directory/ad-hardening/_src/gui.ps1'),
    'active-directory/share-permissions/Set-SharePermissions.ps1':
        ('active-directory/share-permissions/_src/head.ps1', ['active-directory/share-permissions/_src/engine.ps1'], 'active-directory/share-permissions/_src/gui.ps1'),
}

def read(rel):
    with open(os.path.join(ROOT, rel), encoding='utf-8-sig') as f:
        return f.read()

def lib(name):
    with open(os.path.join(LIB, name), encoding='utf-8-sig') as f:
        return f.read()

# Report HTML condivisi: _lib/report/report.ps1 + report.css + report.js iniettati tra i marcatori
# "#region RPT-ASSETS" e "#endregion RPT-ASSETS" dei file elencati (libreria e tool autonomi)
RPT = os.path.join(ROOT, '_lib', 'report')
RPT_TARGETS = ['_lib/toolkit/core_engine.ps1', 'rds/fslogix/compact-vhdx/CompactVHDX-Common.ps1']

def rpt_block():
    def r(n):
        with open(os.path.join(RPT, n), encoding='utf-8-sig') as f:
            return f.read().replace('\r\n', '\n').strip('\n')
    css, js = r('report.css'), r('report.js')
    for name, txt in (('report.css', css), ('report.js', js)):
        if "\n'@" in '\n' + txt:
            raise SystemExit(f'{name}: una riga non puo\' iniziare con \'@')
    return ("#region RPT-ASSETS (generato da _lib/build.py da _lib/report: non modificare qui)\n"
            + r('report.ps1') + "\n$script:RptCss = @'\n" + css + "\n'@\n$script:RptJs = @'\n" + js + "\n'@\n#endregion RPT-ASSETS")

def inject(rel):
    path = os.path.join(ROOT, rel)
    if not os.path.exists(path):
        return
    with open(path, encoding='utf-8-sig', newline='') as f:
        s = f.read().replace('\r\n', '\n')
    a = s.find('#region RPT-ASSETS')
    b = s.find('#endregion RPT-ASSETS')
    if a < 0 or b < 0:
        raise SystemExit(f'{rel}: marcatori RPT-ASSETS mancanti')
    block = rpt_block()
    bad = sorted({c for c in block if ord(c) > 127})
    if bad:
        raise SystemExit(f'_lib/report: caratteri non ASCII {bad}')
    s = s[:a] + block + s[b + len('#endregion RPT-ASSETS'):]
    with open(path, 'w', encoding='utf-8-sig', newline='') as f:
        f.write(s.replace('\n', '\r\n'))
    print('report iniettato:', rel)

for t in RPT_TARGETS:
    inject(t)

for out, (head, engines, gui) in TOOLS.items():
    if not os.path.exists(os.path.join(ROOT, head)):
        print('saltato (sorgenti assenti):', out)
        continue
    s = (read(head) + lib('core_pre.ps1')
         + "\n# Motore: definito una volta, usato dalla GUI, dal runspace di esecuzione e dalla modalita' -NoGui\n$Engine = {\n"
         + lib('core_engine.ps1') + ''.join(read(e) for e in engines) + '}\n'
         + read(gui) + lib('core_main.ps1'))
    bad = sorted({c for c in s if ord(c) > 127})
    if bad:
        raise SystemExit(f'{out}: caratteri non ASCII {bad}')
    s = s.replace('\r\n', '\n').replace('\n', '\r\n')
    path = os.path.join(ROOT, out)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', encoding='utf-8-sig', newline='') as f:
        f.write(s)
    print('generato:', out)


# CompactVHDX-Setup.ps1: equivalente di "Build-CompactVHDXExe.ps1 -SetupOnly -NoSign" (installatore con gli script in base64)
def build_compactvhdx_setup():
    import base64, re
    d = os.path.join(ROOT, 'rds', 'fslogix', 'compact-vhdx')
    builder = os.path.join(d, 'Build-CompactVHDXExe.ps1')
    if not os.path.exists(builder):
        return
    with open(builder, encoding='utf-8-sig') as f:
        b = f.read().replace('\r\n', '\n')
    scripts = re.search(r"^\$scripts = (.+)$", b, re.M).group(1)
    scripts = re.findall(r"'([^']+)'", scripts)
    start = b.index("$setupTemplate = @'\n") + len("$setupTemplate = @'\n")
    end = b.index("\n'@\n    $setupText", start)
    template = b[start:end].replace('\n', '\r\n')
    with open(os.path.join(d, 'CompactVHDX-Common.ps1'), encoding='utf-8-sig') as f:
        version = re.search(r"CVVersion\s*=\s*'([\d.]+)'", f.read()).group(1)
    lines = []
    for sname in scripts:
        with open(os.path.join(d, sname), 'rb') as f:
            data = f.read()
        lines.append("    '%s' = '%s'" % (sname, base64.b64encode(data).decode('ascii')))
    text = template.replace('__VERSION__', version).replace('__PAYLOAD__', '\r\n'.join(lines))
    with open(os.path.join(d, 'CompactVHDX-Setup.ps1'), 'w', encoding='utf-8-sig', newline='') as f:
        f.write(text)
    print('generato: rds/fslogix/compact-vhdx/CompactVHDX-Setup.ps1 (versione %s, non firmato)' % version)

build_compactvhdx_setup()
