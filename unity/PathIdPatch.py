import UnityPy
import UnityPy.config
from UnityPy.enums import ClassIDType
from UnityPy.classes import Shader, PPtr, Sprite

import argparse, os

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        "Adhoc Unity AssetBundle path_id patcher [Shader only]"
    )
    parser.add_argument("path", help="path to the source assetbundle file")
    parser.add_argument("path_ref", help="path to the reference assetbundle file")
    parser.add_argument("output", help="path to store the patched assetbundle file")
    parser.add_argument("--unity", help="unity version to load", default="2022.3.21f1")
    args = parser.parse_args()

    UnityPy.config.FALLBACK_UNITY_VERSION = args.unity
    UnityPy.config.FALLBACK_VERSION_WARNED = True
    path, path_ref, output = args.path, args.path_ref, args.output

    env = UnityPy.load(path)
    candidates = {
        obj.read().m_ParsedForm.m_FallbackName
        for obj in filter(lambda obj: obj.type == ClassIDType.Shader, env.objects)
    }
    print("found %d candidates" % len(candidates))

    env = UnityPy.load(path_ref)
    ref_objects = [
        obj.read()
        for obj in filter(lambda obj: obj.type == ClassIDType.Shader, env.objects)
    ]
    path_id_map = {
        obj.m_ParsedForm.m_Name: obj
        for obj in filter(
            lambda obj: obj.m_ParsedForm.m_Name in candidates, ref_objects
        )
    }
    print("found %d mappings out of %d" % (len(path_id_map), len(candidates)))

    env = UnityPy.load(path)  # ref counted. okay to reinstantiate
    print("-- patching")
    for obj in filter(lambda obj: obj.type == ClassIDType.Shader, env.objects):
        obj = obj.read()
        obj: Shader
        name = obj.m_ParsedForm.m_FallbackName
        ref_obj = path_id_map.get(name, None)
        if ref_obj:
            print(
                "%s\t%d\t%d"
                % (name, obj.m_Dependencies[0].m_PathID, ref_obj.object_reader.path_id)
            )
            obj.m_Dependencies[0].m_PathID = ref_obj.object_reader.path_id
            obj.save()

    os.makedirs(output, exist_ok=True)
    env.save(out_path=output)
    print("-- sanity check")
    env = UnityPy.load(output)
    for obj in filter(lambda obj: obj.type == ClassIDType.Shader, env.objects):
        obj = obj.read()
        obj: Shader
        name = obj.m_ParsedForm.m_FallbackName
        ref_obj = path_id_map.get(name, None)
        if ref_obj:
            print(
                "%s\t%d\t%d"
                % (name, obj.m_Dependencies[0].m_PathID, ref_obj.object_reader.path_id)
            )
            assert obj.m_Dependencies[0].m_PathID == ref_obj.object_reader.path_id

    print("all done. going home.")
