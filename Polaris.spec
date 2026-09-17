# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_all

datas = [('C:/Users/pc/Desktop/RAM/frontend', 'frontend'), ('C:/Users/pc/Desktop/RAM/CopilotToCtrl.exe', '.')]
binaries = [('C:/Users/pc/Desktop/RAM/bin/pdu.exe', 'bin')]
hiddenimports = ['webview', 'clr_loader', 'backend', 'backend.memory_analyzer', 'backend.process_manager', 'backend.diagnostic_engine', 'backend.knowledge_base', 'backend.system_revitalizer', 'backend.crash_analyzer', 'backend.copilot_remapper', 'backend.device_manager', 'backend.disk_health', 'backend.smart_engine', 'backend.smart_database', 'backend.event_log', 'backend.battery_analyzer', 'backend.uninstaller_engine', 'backend.storage_analyzer', 'backend.win_utils', 'backend.server']
tmp_ret = collect_all('webview')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]


a = Analysis(
    ['C:/Users/pc/Desktop/RAM/main.py'],
    pathex=[],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='Polaris',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    uac_admin=True,
    icon=['C:/Users/pc/Desktop/RAM/app_icon.ico'],
)
