# Compile (Watch mode)
```bash
npm run build <path to script>
# Example:
npm run build SetTargetFramerate.ts
```

# Attach
```bash
npm run attach <frida arguments>
# Example:
npm run attach -- -U プロセカ
npm run attach -- -n UmamusumePrettyDerby.exe
```

# BuildGadget
```bash
python BuildGadget.py --arch <target architecture> --config <frida-gadget config JSON file> --inject-target <target lib to inject> <source apk>
# Example (arm64, injects into libunity.so, produces app.apk/ folder containing signed APKs):
python BuildGadget.py app.apk
# Example (same as above with custom config)
python BuildGadget.py --config config.json app.apk
```
