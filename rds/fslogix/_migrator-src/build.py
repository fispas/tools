"""Genera i tre migratori single-file da questi sorgenti.
Uso (dalla root del repo):  python rds/fslogix/_migrator-src/build.py
"""
import os
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)  # rds/fslogix
TOOLS = {
    'upd': ('upd-to-fslogix', 'Convert-UPDToFSLogix.ps1'),
    'roaming': ('roaming-to-fslogix', 'Convert-RoamingProfileToFSLogix.ps1'),
    'local': ('local-to-fslogix', 'Convert-LocalProfileToFSLogix.ps1'),
}
def r(name):
    with open(os.path.join(HERE, name), encoding='utf-8-sig') as f:
        return f.read()
for key, (folder, name) in TOOLS.items():
    s = (r(key + '_head.ps1') + r('core_pre.ps1')
         + "\n# Motore: definito una volta, usato dalla GUI, dal runspace di esecuzione e dalla modalita' -NoGui\n$Engine = {\n"
         + r('core_engine.ps1') + r(key + '_engine.ps1') + '}\n' + r(key + '_gui.ps1') + r('core_main.ps1'))
    s = s.replace('\r\n', '\n').replace('\n', '\r\n')
    out = os.path.join(ROOT, folder, name)
    with open(out, 'w', encoding='utf-8-sig', newline='') as f:
        f.write(s)
    print(out)
