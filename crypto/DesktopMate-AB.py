import base64, os
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA1
from Crypto.Util.Padding import unpad
from Crypto.Util import Counter


def decrypt_filename(s: str):
    s = s.replace("-", "/")
    s = base64.b64decode(s)
    cipher = AES.new(
        b"YVe2SngRFQNCbPW67xrANOKMaDP8Qopn", AES.MODE_CBC, iv=b"3RSFHrtWxi7d1eAP"
    )
    return unpad(cipher.decrypt(s), 16).decode()


def derive_key(filename: str):
    salt = filename + filename
    return PBKDF2(
        b"sCHcfTxIpgO2tusgnlNqKVKsdopir0JH",
        salt.encode(),
        32,
        count=1000,
        hmac_hash_module=SHA1,
    )


os.chdir(
    r"C:\Users\mos9527\Desktop\Desktop Mate\DesktopMate_Data\StreamingAssets\AssetBundle"
)
fn = "Yp2FltrhJDOM4HFiNFNjow=="
with open(fn, "rb") as f:
    bs = 128 // 8
    nb = 1
    fn = decrypt_filename(fn)
    key = derive_key(fn)
    # cipher = AES.new(key, AES.MODE_ECB)
    # with open(fn, "wb") as fout:
    #     while block := f.read(bs):
    #         xorblock = nb.to_bytes(8, "little") + b"\x00" * (bs - 8)
    #         xorblock = cipher.encrypt(xorblock)
    #         block = bytes((a ^ b for a, b in zip(block, xorblock)))
    #         fout.write(block)
    #         nb += 1
    cipher = AES.new(key, AES.MODE_CTR, counter=Counter.new(128, little_endian=True))
    with open(fn, "wb") as fout:
        while block := f.read(bs):
            block = cipher.decrypt(block)
            fout.write(block)
            nb += 1
