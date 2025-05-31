// Set Unity application target frame rate to 120 FPS
import "frida-il2cpp-bridge";

Il2Cpp.perform(() => {
    var asm = Il2Cpp.domain.assembly("UnityEngine.CoreModule").image;    
    var application = asm.class("UnityEngine.Application");    
    application.method("set_targetFrameRate", 1).invoke(120);
});