import random
def generate_path_id(src: str) -> int:
    pptr = hash(src) & (2**63 - 1)
    pptr = pptr // 1e5
    pptr = int(pptr) * int(1e5)
    return pptr + random.randint(0, int(1e5) - 1)

def generate_cab_name(src: str) -> str:
    pptr = generate_path_id(src)
    salt = random.randint(0, 2**32 - 1)
    return f"CAB_MOD_{pptr:0>16x}_{salt:0>8x}"

import UnityPy
from UnityPy.classes import AssetBundle
from UnityPy.files import SerializedFile

def regen_unique_bundle(src, packer: str = 'lz4', outpath: str = None):
    env = UnityPy.load(src)
    path_id_remap = {}
    for obj in env.objects:
        if obj.type.name == "AssetBundle":
            data = obj.read()
            data : AssetBundle
            for i, (name, asset) in enumerate(data.m_Container):
                new_id = generate_path_id(name)
                path_id_remap[new_id] = asset.asset.path_id
                print(f'REGEN Asset\t{name}->{new_id}')
                asset.asset.read().object_reader.path_id = new_id
                asset.asset.m_PathID = new_id                
            data.save()
    cab_name_remap = {}
    for i, (name, file) in enumerate(env.file.files.items()):
        for new,old in path_id_remap.items():
            if type(file) == SerializedFile:
                file : SerializedFile      
                new_name = generate_cab_name(name)
                cab_name_remap[name] = new_name
                cab_name_remap[f'{name}.resS'] = f'{new_name}.resS'
                if old in file.objects:
                    file.objects[new] = file.objects[old]
                    del file.objects[old]
                    print(f'REGEN PPtr\t{name}::{old}->{new}')
                file.save()   
    for old, new in cab_name_remap.items():
        env.file.files[new] = env.file.files[old]
        del env.file.files[old]
        print(f'REGEN File\t{old}->{new}')
    env.save(pack=packer, out_path=outpath)

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Regenerate unique path IDs in Unity AssetBundle, allowing modified content to coexist with original files.")
    parser.add_argument("src", help="Path to the source assetbundle file")
    parser.add_argument("--packer", default="lz4", help="Packer to use for the regenerated bundle")
    parser.add_argument("--outpath", help="Output path for the regenerated assetbundle")
    args = parser.parse_args()
    
    regen_unique_bundle(args.src, packer=args.packer, outpath=args.outpath)