import "frida-il2cpp-bridge";
Il2Cpp.perform(() => {
    console.log("Script reload.");
    const game = Il2Cpp.domain.assembly("Assembly-CSharp").image;
    const unity = Il2Cpp.domain.assembly("UnityEngine.CoreModule").image;    
    const mscorlib = Il2Cpp.domain.assembly("mscorlib").image;
    const system = Il2Cpp.domain.assembly("System").image;
    const web = Il2Cpp.domain.assembly("UnityEngine.UnityWebRequestModule").image;
    const cri = game.class('CriWare.CriWareErrorHandler');
    const object = mscorlib.class('System.Object');
    // const delegate = Il2Cpp.delegate(cri.nested('Callback'), (msg : Il2Cpp.String) => {
    //     console.log("[CRI] " + msg);
    // });
    // cri.method("add_OnCallback").invoke(delegate);
    Il2Cpp.installExceptionListener('all');
    web.class("UnityEngineInternal.WebRequestUtils").method("MakeInitialUrl").implementation = function (url1, url2) {
        console.log("[WebRequestUtils] MakeInitialUrl called with: " + url1 + ", " + url2);
        return this.method<Il2Cpp.Object>("MakeInitialUrl").invoke(url1, url2);
    }    
    system.class('System.Uri').method('CreateThis').implementation = function (uriString, dontEscape, uriKind) {
        console.log("[System.Uri] CreateThis called with: " + uriString, dontEscape, uriKind);
        return this.method<Il2Cpp.Object>("CreateThis").invoke(uriString, dontEscape, uriKind);
    };
    // Il2Cpp.trace(true).classes(
    //     game.class("CP.LogUtilityIO"),
    //     game.class("ThreadSafeLogUtility"),
    //     // game.class("Sekai.SoundManager"),
    //     // game.class("CriWare.CriAtomExPlayer"),
    //     game.class("Sekai.APICore`2").inflate(object, object),
    //     // game.class("CriWare.CriAtomExAcb"),
    //     // game.class("CP.CRI.CriCorePlayer"),
    //     // game.class('CriWare.CriWareErrorHandler'),
    //     // game.class('CriWare.CriErrorNotifier'),
    //     // game.class("Sekai.SUS.Converter"),
    //     unity.class("UnityEngine.Debug"),  
    //     unity.class("UnityEngine.DebugLogHandler"),   
    //     unity.class("UnityEngine.Logger"),   
    //     web.class("UnityEngineInternal.WebRequestUtils"),
    // ).and().attach();
}); 