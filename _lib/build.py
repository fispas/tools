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
        ('active-directory/ad-hardening/_src/head.ps1', ['active-directory/ad-hardening/_src/engine.ps1', 'active-directory/ad-hardening/_src/hardening.ps1'], 'active-directory/ad-hardening/_src/gui.ps1'),
    'active-directory/share-permissions/Set-SharePermissions.ps1':
        ('active-directory/share-permissions/_src/head.ps1', ['active-directory/share-permissions/_src/engine.ps1'], 'active-directory/share-permissions/_src/gui.ps1'),
}

def read(rel):
    with open(os.path.join(ROOT, rel), encoding='utf-8-sig') as f:
        return f.read()

def lib(name):
    with open(os.path.join(LIB, name), encoding='utf-8-sig') as f:
        return f.read()

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
