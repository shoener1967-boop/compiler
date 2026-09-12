# Detection Monitor (iOS 16 / roothide)

Diagnostic tweak for observing common jailbreak-detection API calls in an app you own or are authorized to test. It does **not** bypass or alter the result of any check.

## Build

Use roothide Theos on macOS/Linux:

```sh
export THEOS=/path/to/roothide-theos
make package THEOS_PACKAGE_SCHEME=roothide FINALPACKAGE=1
```

Install the generated `.deb` with Sileo/Zebra. The package is intended for Dopamine2-roothide on iOS 16.7.x.

## Configure

Edit `/var/mobile/Library/Preferences/com.shosh.detectionmonitor.plist` (or use a preference editor):

- `Enabled` — boolean, default `YES`
- `TargetBundle` — exact bundle ID; empty means every injected app
- `LogAllPaths` — boolean, default `NO`; when disabled, only suspicious paths are logged
- `IncludeBacktrace` — boolean, default `NO`

After changing preferences, restart the target app.

Logs are written to:

```text
/var/mobile/Library/Logs/DetectionMonitor/<bundle-id>.log
```

The monitor records timestamp, API, argument, return value, errno and optionally a short backtrace. It leaves return values untouched.

## Limitations

It cannot see checks implemented entirely in assembly, kernel code, server responses, or APIs that are not hooked. Network/server-side checks require separate traffic inspection. Start with one target bundle to reduce noise and instability.
