import "frida-il2cpp-bridge";
Il2Cpp.perform( () => {
    console.log("Script reload");
    const sr =  Il2Cpp.domain.assembly("StompyRobot.SRDebugger.dll").image;
    const srf = Il2Cpp.domain.assembly("StompyRobot.SRF").image;
    const unity = Il2Cpp.domain.assembly("UnityEngine.CoreModule").image;   
    const service = srf.class("SRF.Service.SRServiceManager");
    const srdebug = sr.class("SRDebug");
        Il2Cpp.trace(true).classes(
        unity.class("UnityEngine.Debug"),  
        unity.class("UnityEngine.DebugLogHandler"),   
        unity.class("UnityEngine.Logger"),   
    ).and().assemblies(        
    ).and().attach();

    var init = srdebug.method('get_IsInitialized').invoke();
    if (!init){
        console.log("SR Init");
        srdebug.method('Init').invoke();
        console.log("SR Initialized");
    }
    var instance = srdebug.method('get_Instance').invoke();
    console.log("SR Instance: " + instance);
    instance.method('ShowDebugPanel').invoke(false);
}, "main");
