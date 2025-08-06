'''Bundle Frida Gadget into Android APKs

Tools used:
- github.com/BotPeaches/Apktool
- github.com/patrickfav/uber-apk-signer
- github.com/obfusk/reproducible-apk-tools (for zipalign w/ >2GB files on Windows)
'''
import os, lzma, shutil, lief, sys
from tqdm import tqdm
from requests import get
from frida import __version__

tmp = os.path.join(os.path.dirname(__file__), '.temp')
os.makedirs(tmp, exist_ok=True)

def download(src, dest, skip_exists=False):
    if skip_exists and os.path.exists(dest):
        return dest
    with open(dest + '.tmp', 'wb') as f:
        resp = get(src, stream=True)
        resp.raise_for_status()
        for chunk in tqdm(resp.iter_content(1<<10), total=int(resp.headers.get('Content-Length', 0)) // (1<<10), unit='KB', desc=os.path.basename(dest)):
            f.write(chunk)
    os.rename(dest + '.tmp', dest)
    return dest

def download_gadget(arch: str = 'android-arm64') -> None:
    url = f'https://github.com/frida/frida/releases/download/{__version__}/frida-gadget-{__version__}-android-{arch}.so.xz'
    gadget = f'frida-gadget-{__version__}-android-{arch}.so'

    dest = os.path.join(tmp, gadget)

    if not os.path.exists(dest):
        archived = download(url, dest + '.xz')            
        with lzma.open(archived, 'rb') as f_in, open(dest, 'wb') as f_out:
            for chunk in tqdm(iter(lambda: f_in.read(1<<20), b''), total=os.path.getsize(dest + '.xz') // (1<<20), unit='MB', desc='uncompress gadget'):
                f_out.write(chunk)
    return dest

def apktool(*args):
    url = 'https://github.com/iBotPeaches/Apktool/releases/download/v2.12.0/apktool_2.12.0.jar'
    dest = os.path.join(tmp, 'apktool.jar')
    download(url, dest, skip_exists=True)
    return os.system(f'java -jar {dest} {" ".join(args)}')

def uber_apk_signer(*args):
    url = 'https://github.com/patrickfav/uber-apk-signer/releases/download/v1.3.0/uber-apk-signer-1.3.0.jar'
    dest = os.path.join(tmp, 'uber-apk-signer.jar')
    download(url, dest, skip_exists=True)
    return os.system(f'java -jar {dest} {" ".join(args)}')

def __main__(args):    
    gadget_path = download_gadget(args.arch)
    tmp_dir = os.path.join(tmp, 'apk')
    if os.path.exists(tmp_dir):
        shutil.rmtree(tmp_dir)
    assert apktool('d', '-o', tmp_dir, '--no-src', args.infile) == 0, 'Failed to decompile APK'
    lib_dir = os.path.join(tmp_dir, 'lib')
    target_lib_dir = None
    for r,d,fs in os.walk(lib_dir):
        if args.arch in r:
            for f in fs:
                if f == args.inject_target:
                    target_lib_dir = r
    assert target_lib_dir, f'Target library {args.inject_target} not found in APK'
    dest_lib = os.path.join(target_lib_dir, args.inject_target)    
    elf = lief.ELF.parse(dest_lib)
    elf.add_library('libgadget.so')
    elf.write(dest_lib)
    shutil.copy(gadget_path, os.path.join(target_lib_dir, 'libgadget.so'))
    if args.config is None:
        with open(os.path.join(target_lib_dir,'libgadget.config.so'), 'w') as f:
            f.write('''{"interaction": {"type": "listen","address": "0.0.0.0","port": 27042,"on_port_conflict": "fail","on_load": "wait"}}''')
    else:
        shutil.copyfile(args.config, os.path.join(target_lib_dir, 'libgadget.config.so'))
    outfile = os.path.splitext(os.path.basename(args.infile))[0] + '-gadget.apk'
    outfile = os.path.join(os.path.dirname(args.infile), outfile)
    tmpbuild = os.path.join(tmp, 'build.apk')
    assert apktool('b', '-o', tmpbuild, tmp_dir) == 0, 'Failed to build APK'
    if sys.platform == 'win32':
        zipalign_url = 'https://raw.githubusercontent.com/obfusk/reproducible-apk-tools/refs/heads/master/zipalign.py'
        zipalign_dest = os.path.join(tmp, 'zipalign.py')    
        download(zipalign_url, zipalign_dest, skip_exists=True)
        zipalign_shim = os.path.join(tmp, 'zipalign.cmd')
        with open(zipalign_shim, 'w') as f:
            # Very ugly. Though works.
            # Uber signer uses zipalign like this:
            # SIGNING: zipalign -p -v 4 [debug apk] [aligned apk]
            # CHECKING: zipalign -c -v 4 [aligned apk]
            # We always pass the check and ignore alignment size.
            f.write(f'''
IF "%4"=="" GOTO :EOF
{sys.executable} {zipalign_dest} -p %4 %5\n''')
        assert uber_apk_signer('--zipAlignPath', f'"{zipalign_shim}"', '--apks', tmpbuild, '-o', outfile) == 0, 'Failed to sign APK'
    else:
        assert uber_apk_signer('--apks', tmpbuild, '-o', outfile) == 0, 'Failed to sign APK'
    print('Package ready at', outfile)
if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Bundle Frida Gadget into Android APKs')
    parser.add_argument('--arch', default='arm64', help='Architecture of Frida Gadget to download (default: arm64)')
    parser.add_argument('--config', default=None, help='Path to gadget config file. Leave empty to listen on 0.0.0.0:27042')
    parser.add_argument('--inject-target', default='libunity.so', help='Target library to inject Frida gadget into (default: libunity.so)')
    parser.add_argument('infile', help='Path to Unity Android Player APK file')
    args = parser.parse_args()
    __main__(args)
