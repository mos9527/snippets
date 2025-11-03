import "frida-il2cpp-bridge";
Il2Cpp.perform(() => {
    console.log("Script reload");
    const game = Il2Cpp.domain.assembly("Assembly-CSharp").image;
    const unity = Il2Cpp.domain.assembly("UnityEngine.CoreModule").image;    
    const mscorlib = Il2Cpp.domain.assembly("mscorlib").image;
    Il2Cpp.installExceptionListener('all');
    Il2Cpp.trace(true).classes(
        game.class("CP.LogUtilityIO"),
        game.class("ThreadSafeLogUtility"),
        game.class("Sekai.SoundManager"),
        game.class("CriWare.CriAtomExPlayer"),
        game.class("CP.CRI.CriCorePlayer"),
        game.class('CriWare.CriWareErrorHandler'),
        // game.class("Sekai.SUS.Converter"),
        unity.class("UnityEngine.Debug"),  
        unity.class("UnityEngine.DebugLogHandler"),   
        unity.class("UnityEngine.Logger"),   
    ).and().assemblies(        
    ).and().attach();
});