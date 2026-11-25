// harness.js -- call-site instrumentation harness for Frida
//
// Hooks one function inside a native module and records, per call:
//   - the return address relative to the module base (the call site)
//   - the first argument as a pointer
//   - the return value
//
// The output is a call-site histogram, not a raw dump. On a hot function
// the raw log is useless -- the distribution is the signal. The sites that
// appear thousands of times are the ones on the hot path; the ones that
// appear once are the ones worth reading.
//
// Usage:
//   frida -U -f <package> -l harness.js --no-pause
//   frida -H 127.0.0.1:31337 -f <package> -l harness.js --no-pause
//
// Tested with frida 16.x against arm64 Android.

var CONFIG = {
    module: "libtarget.so",      // module to wait for
    offset: 0x0,                 // function offset from module base
    logPath: "/data/local/tmp/harness.log",
    flushEvery: 5000,            // ms between log writes
    maxSites: 512,               // histogram ceiling, guards against runaway
    forceReturn: null            // null = observe only; number = replace retval
};

var base = null;
var hooked = false;
var sites = {};                  // relOffset -> { n, lastArg, lastRet }
var siteCount = 0;
var total = 0;
var started = Date.now();

function hex(n) {
    return "0x" + (n >>> 0).toString(16);
}

function flush() {
    var lines = [];
    lines.push("module  = " + CONFIG.module);
    lines.push("offset  = " + hex(CONFIG.offset));
    lines.push("base    = " + base);
    lines.push("hooked  = " + (hooked ? "yes" : "no"));
    lines.push("total   = " + total);
    lines.push("uptime  = " + Math.round((Date.now() - started) / 1000) + "s");
    lines.push("");
    lines.push("sites   n        arg0         ret");

    var keys = Object.keys(sites);
    keys.sort(function (a, b) { return sites[b].n - sites[a].n; });

    for (var i = 0; i < keys.length; i++) {
        var s = sites[keys[i]];
        lines.push(pad(keys[i], 8) + pad(String(s.n), 9) +
                   pad(s.lastArg, 13) + s.lastRet);
    }

    try { File.writeAllText(CONFIG.logPath, lines.join("\n") + "\n"); } catch (e) { }
}

function pad(v, w) {
    v = String(v);
    while (v.length < w) { v += " "; }
    return v;
}

function install() {
    Interceptor.attach(base.add(CONFIG.offset), {
        onEnter: function (args) {
            this.site = this.returnAddress.sub(base).toInt32();
            this.arg0 = args[0];
        },
        onLeave: function (retval) {
            var ret = retval.toInt32();
            total++;

            var key = hex(this.site);
            var s = sites[key];
            if (!s) {
                if (siteCount >= CONFIG.maxSites) { return; }
                s = sites[key] = { n: 0, lastArg: "", lastRet: 0 };
                siteCount++;
            }

            s.n++;
            s.lastArg = this.arg0;
            s.lastRet = ret;

            if (CONFIG.forceReturn !== null) {
                retval.replace(ptr(CONFIG.forceReturn));
            }
        }
    });

    hooked = true;
    flush();
}

var tries = 0;
var wait = setInterval(function () {
    tries++;
    var m = Process.findModuleByName(CONFIG.module);
    if (m) {
        base = m.base;
        clearInterval(wait);
        try { install(); } catch (e) { base = "error: " + e.message; flush(); }
        setInterval(flush, CONFIG.flushEvery);
        return;
    }
    if (tries > 240) {
        clearInterval(wait);
        base = "timeout";
        flush();
    }
}, 500);
