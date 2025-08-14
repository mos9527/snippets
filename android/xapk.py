import os, zipfile, shutil
from tqdm import tqdm
from requests import get
from pathlib import Path

tmp = Path(__file__).parent / '.temp'
tmp.mkdir(exist_ok=True)

def download(src : Path, dest : Path, skip_exists=False):
    if skip_exists and dest.exists():
        return dest
    with open(dest.with_suffix('.tmp'), 'wb') as f:
        resp = get(src, stream=True)
        resp.raise_for_status()
        for chunk in tqdm(resp.iter_content(1<<10), total=int(resp.headers.get('Content-Length', 0)) // (1<<10), unit='KB', desc=f'Download {dest.name}'):
            f.write(chunk)
    dest.with_suffix('.tmp').rename(dest)
    return dest

def runtool(cmd):
    print(cmd)
    return os.system(cmd)

def apkeditor(*args):
    url = 'https://github.com/REAndroid/APKEditor/releases/download/V1.4.5/APKEditor-1.4.5.jar'
    dest = tmp / 'apkeditor.jar'
    download(url, dest, skip_exists=True)
    return runtool(f'java -jar {dest} {" ".join(args)}')

def apktool(*args):    
    url = 'https://github.com/iBotPeaches/Apktool/releases/download/v2.12.0/apktool_2.12.0.jar'
    dest = tmp / 'apktool.jar'
    download(url, dest, skip_exists=True)
    return runtool(f'java -jar {dest} {" ".join(args)}')

def uber_apk_signer(*args):
    url = 'https://github.com/patrickfav/uber-apk-signer/releases/download/v1.3.0/uber-apk-signer-1.3.0.jar'
    dest = tmp / 'uber-apk-signer.jar'
    download(url, dest, skip_exists=True)
    return runtool(f'java -jar {dest} {" ".join(args)}')

def main_extract(path_in: Path, path_out: Path):
    path_out.mkdir(exist_ok=True)
    if path_in.suffix != '.apk':
        apk_path = path_out / path_in.name
        apk_path = apk_path.with_suffix('.apk')
        splitdir = tmp / 'split'
        splitdir.mkdir(exist_ok=True)
        with zipfile.ZipFile(path_in, 'r') as zf:
            zf.extractall(splitdir)
        apkeditor('m', '-i', str(splitdir), '-o', str(apk_path))
    else:
        apk_path = path_in
    out_path = path_out / apk_path.stem
    shutil.rmtree(str(out_path), ignore_errors=True)
    apktool('d', '-f', '-o', str(out_path), '--no-src', '--no-assets', str(apk_path))


def main_build(path_in: Path, path_out: Path):
    assert path_out.suffix == '.apk', "output path must be an APK file"
    apkfile = list(path_in.glob('*.apk'))
    assert len(apkfile) == 1, "expected exactly one APK file in input folder, got %d" % len(apkfile)
    apkfile = Path(apkfile[0])
    unsigned_path = tmp / Path(apkfile.name).with_suffix('.unsigned.apk')
    apktool('b', str(path_in / apkfile.stem), '-o', str(unsigned_path))
    tmp_sign = tmp / Path(apkfile.name).with_suffix('')
    shutil.rmtree(str(tmp_sign), ignore_errors=True)
    uber_apk_signer('--apks', str(unsigned_path), '-o', str(tmp_sign))
    apkfile = list(tmp_sign.glob('*.apk'))
    assert len(apkfile) == 1, "expected exactly one signed APK file"
    path_out.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(str(apkfile[0]), str(path_out))    

def __main__(args):
    path_in = Path(args.input)
    path_out = Path(args.output)
    if path_in.is_dir():
        main_build(path_in, path_out)
    else:
        main_extract(path_in, path_out)

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Extract, build and sign APK/XAPK bundles')
    parser.add_argument('input', help='Path to APK/XAPK file, or extracted folder')
    parser.add_argument('output', help='Path to output APK file, or extracted folder')
    args = parser.parse_args()
    __main__(args)