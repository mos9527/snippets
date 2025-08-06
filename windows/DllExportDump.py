import sys, os, ctypes
from pefile import PE
from os.path import join

windir = ctypes.create_unicode_buffer(260)
ctypes.windll.kernel32.GetWindowsDirectoryW(windir, 260)
windir = windir.value
sys32dir = os.path.join(windir, "System32")
path = sys.argv[-1]
for path in {path, join(windir, path), join(sys32dir, path)}:
    if os.path.exists(path):
        break
else:
    print("path cannot be resolved.", file=sys.stderr)
    print('usage: python DllExportDump.py <path to dll, or the dll filename itself (e.g. dinput8.dll)>', file=sys.stderr)
    print('Export DLL Exports as `#pragma comment(linker,...`, which then can be used by MSVC to export them again.', file=sys.stderr)
    sys.exit(1)
dllname = ".".join(os.path.basename(path).split(".")[:-1])
pathname = os.path.dirname(path).replace("\\", "\\\\")
print("// ", path, "(%s)" % dllname)
pe = PE(path)
for export in pe.DIRECTORY_ENTRY_EXPORT.symbols:
    if export.name:
        name = export.name.decode("utf-8")
        print(
            f'#pragma comment(linker, "/EXPORT:{name}={pathname}\\\\{dllname}.{name}")'
        )