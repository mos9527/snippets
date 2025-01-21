import UnityPy
import UnityPy.config
from UnityPy.enums import ClassIDType
from UnityPy.classes import Shader, PPtr, Sprite

UnityPy.config.FALLBACK_UNITY_VERSION = "2022.3.21f1"
UnityPy.config.FALLBACK_VERSION_WARNED = True

path = "/Users/mos9527/pcs_ios"
path_ref = "/Users/mos9527/Library/Containers/io.playcover.PlayCover/Applications/com.sega.pjsekai.app/Data"
output = "/Users/mos9527/AssetMod"

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
    for obj in filter(lambda obj: obj.m_ParsedForm.m_Name in candidates, ref_objects)
}
print("found %d mappings out of %d" % (len(path_id_map), len(candidates)))

env = UnityPy.load(path)  # ref counted. okay to reinstantiate
for obj in filter(lambda obj: obj.type == ClassIDType.Shader, env.objects):
    obj = obj.read()
    obj: Shader
    name = obj.m_ParsedForm.m_FallbackName
    ref_obj = path_id_map[name]
    print(
        "%s [%d] -> [%d]"
        % (name, obj.m_Dependencies[0].m_PathID, ref_obj.object_reader.path_id)
    )
    obj.m_Dependencies[0].m_PathID = ref_obj.object_reader.path_id
    obj.save()

env.save(out_path=output)
