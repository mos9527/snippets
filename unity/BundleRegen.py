
import UnityPy
from UnityPy.classes import Texture2D, AssetBundle, TextAsset, MonoBehaviour
from UnityPy.enums import TextureFormat
from UnityPy.files import SerializedFile, BundleFile

def save_as_unique_bundle(file : BundleFile, version : str = UnityPy.config.FALLBACK_UNITY_VERSION) -> bytes:
    """Regenerates PPtrs for all assets within a bundle environment.

    You HAVE to save the environment after calling this function.
    """
    assert type(file) == BundleFile
    def generate_cab_name(ab_name: str) -> str:
        import hashlib
        return 'MOD-' + hashlib.md5(ab_name.encode("utf-8")).hexdigest()
    # Effectively commit changes
    src = file.save(packer='original')
    env = UnityPy.load(src)
    cab_name_remap = {}
    for i, (name, file) in enumerate(env.file.files.items()):
        if type(file) == SerializedFile:
            file: SerializedFile
            file.set_version(version)
            new_name = generate_cab_name(file.assetbundle.m_Name)
            cab_name_remap[name] = new_name                
            # Shuffle AssetBundle (PathID always 1) to end of object list
            # Probably unnecessary, but runtime does this all the time.
            assetbundle = file.objects[1]
            del file.objects[1]
            file.objects[1] = assetbundle
            # Save. Packer does not apply to SerializedFile
            file.save()
    for old, new in cab_name_remap.items():
        if old in env.file.files:
            env.file.files[new] = env.file.files[old]
            del env.file.files[old]
    # Optional. Shouldn't affect loading    
    env.file.version_engine = version
    return env.file.save(packer='original')
