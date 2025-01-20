import UnityPy
from UnityPy.enums import ClassIDType
from UnityPy.classes import Shader, PPtr, Sprite

path = "/Users/mos9527/one_frame"
output = "/Users/mos9527/AssetMod"
env = UnityPy.Environment(path)


# for obj in filter(lambda obj: obj.type == ClassIDType.Sprite, env.objects):
#     obj = obj.read()
#     obj: Sprite
#     obj.m_RD.texture.m_PathID = -5502281873464671095
#     obj.save()

path_id_map = {-9070518480369046860: -1686991803859250934}
for obj in filter(lambda obj: obj.type == ClassIDType.Shader, env.objects):
    obj = obj.read()
    obj: Shader
    for dependency in obj.m_Dependencies:
        dependency: PPtr
        dependency.m_PathID = path_id_map.get(dependency.path_id, dependency.path_id)
    obj.save()

env.save(out_path=output)
