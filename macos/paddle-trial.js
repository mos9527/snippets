// https://www.52pojie.cn/thread-1751135-1-1.html
const targetClass = ObjC.classes.PADProduct;
let methodName = "- trialDaysRemaining";
Interceptor.attach(targetClass[methodName].implementation, {
    onEnter(args) {
        const instance = ObjC.Object(args[0]);
        console.log(instance);
        instance.resetTrial();
        console.log("Reset Trial Success!");
    },
    onLeave(retval) {
        console.log("Trial Days Remaining: ", retval);
    }
});