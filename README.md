# frida-harness

A minimal call-site instrumentation harness for Frida. One function in, a
call-site histogram out.

## Why a histogram

When you hook a function that runs 400k times, the raw call log is noise.
What matters is the distribution:

- a call site that appears **thousands** of times is on the hot path
- a call site that appears **once** is the interesting one — it is usually
  the initialization path, the loader, or the thing that only happens when
  the user does the specific action you care about
- a call site that appears with a **constant argument** and a changing
  return value is a getter

That sorting is the entire job. The harness does it for you.

## Config

Everything lives in one block at the top of `harness.js`:

```js
var CONFIG = {
    module: "libtarget.so",      // module to wait for
    offset: 0x0,                 // function offset from module base
    logPath: "/data/local/tmp/harness.log",
    flushEvery: 5000,            // ms between log writes
    maxSites: 512,               // histogram ceiling
    forceReturn: null            // null = observe only; number = replace retval
};
```

`forceReturn` turns the harness from an observer into a patcher without
touching memory: only the return value is replaced, so any internal
consistency check on the object state still passes.

## Usage

```
frida -U -f com.example.app -l harness.js --no-pause
```

Or against a device running `frida-server` on a non-default port:

```
frida -H 127.0.0.1:31337 -f com.example.app -l harness.js --no-pause
```

Pull the log:

```
adb shell "cat /data/local/tmp/harness.log"
```

## Output

```
module  = libtarget.so
offset  = 0x25d234
base    = 0x7a2d082000
hooked  = yes
total   = 414979
uptime  = 240s

sites   n        arg0         ret
0x293f1c 202118  0x7c2670abcc 30355
0x293f28 198441  0x7c2670abcc 30355
0x293e98 10421   0x7c2670abe4 101
0x2fd748 3918    0x7c2670abe4 101
```

Read it as: two sites read the same pointer and get the same value —
those are the two halves of one accessor. The next pair reads a pointer
`+0x18` away and gets a different value — same struct, adjacent field.

## Notes

- The address of a heap object changes every launch. The **call-site
  offset** does not. Always key on `returnAddress - moduleBase`.
- `toInt32()` on a 64-bit return truncates. For 64-bit values use
  `retval.toUInt64()` and log with `.toString()`.
- Writes are best-effort. On Android 11+ the app's external storage may
  reject the write before `onCreate` returns; the harness retries on the
  flush timer for this reason.

## License

MIT
