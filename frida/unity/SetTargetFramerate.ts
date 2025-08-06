// Set Unity application target frame rate to 120 FPS
import "frida-il2cpp-bridge";

Il2Cpp.perform(() => {
    var asm = Il2Cpp.domain.assembly("UnityEngine.CoreModule").image;    
    var application = asm.class("UnityEngine.Application");    
    var set_targetFrameRate = application.method("set_targetFrameRate");
    set_targetFrameRate.invoke(160);
    set_targetFrameRate.implementation = function (frameRate) {
        console.log("* Game setting target frame rate to " + frameRate);
        return this.method<void>("set_targetFrameRate").invoke(120);
    }
});