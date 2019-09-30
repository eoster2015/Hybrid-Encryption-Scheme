# -*- mode: python -*-

block_cipher = None


a = Analysis(['__main__.py'],
             pathex=['C:\\Users\\ericostertkd\\Documents\\CIS 5371 Practical Aspects of Modern Cryptography 2018\\eoster2015_cis5371_final_project\\eoster2015_cis5371_final_project_demo'],
             binaries=[],
             datas=[],
             hiddenimports=[],
             hookspath=[],
             runtime_hooks=[],
             excludes=[],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher,
             noarchive=False)
pyz = PYZ(a.pure, a.zipped_data,
             cipher=block_cipher)
exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,
          [],
          name='eoster2015_cis5371_final_project',
          debug=False,
          bootloader_ignore_signals=False,
          strip=False,
          upx=True,
          runtime_tmpdir=None,
          console=True )
