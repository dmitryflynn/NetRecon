# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['netlogic.py'],
    pathex=[],
    binaries=[],
    datas=[('src', 'src')],
    hiddenimports=['src.scanner', 'src.cve_correlator', 'src.nvd_lookup', 'src.osint', 'src.reporter', 'src.tls_analyzer', 'src.header_audit', 'src.takeover', 'src.stack_fingerprint', 'src.dns_security', 'src.json_bridge', 'ssl', 'certifi', 'requests', 'concurrent.futures'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['tkinter', 'matplotlib', 'numpy'],
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
    name='netlogic_engine',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
