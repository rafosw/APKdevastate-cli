# APKdevastate CLI — C++17 Linux Edition

> C++17 CLI port — static APK malware analyzer

---

## Features

| Feature | Status |
|---|---|
| APK decompilation via `apktool` | ✅ |
| AndroidManifest.xml parsing | ✅ |
| MD5 / SHA-1 / SHA-256 hashing | ✅ |
| Permission analysis (aapt) | ✅ |
| Dangerous permission flagging | ✅ |
| RAT signature scanning | ✅ |
| Certificate info (apksigner) | ✅ |
| Native `.so` library detection | ✅ |
| Dynamic class loader detection | ✅ |
| Obfuscation / packing heuristics | ✅ |
| Trusted org cert verification | ✅ |
| jadx fallback for encrypted APKs | ✅ |
| Colored ANSI terminal output | ✅ |
| Progress indicators | ✅ |

---

## Requirements

### Runtime tools (must be on PATH or in `resources/`)
| Tool | Purpose |
|---|---|
| `java` | Run apktool and apksigner |
| `apktool` / `apktool.jar` | APK decompilation |
| `aapt` | Permission + package info |
| `apksigner.jar` | Certificate extraction |
| `jadx` *(optional)* | Encrypted APK fallback |

### Build dependencies
| Library | Package (Debian/Ubuntu) |
|---|---|
| OpenSSL | `libssl-dev` |
| libzip | `libzip-dev` |
| nlohmann/json | auto-downloaded if absent |
| CMake ≥ 3.16 | `cmake` |
| GCC/Clang C++17 | `g++` |

---

## Build

```bash
chmod +x build.sh
./build.sh             # debug build
./build.sh --release   # optimised build
./build.sh --clean     # wipe build dir first
```

The script auto-downloads `nlohmann/json` if not present on your system.

---

## Usage

```bash
./build/bin/apkdevastate <file.apk>
./build/bin/apkdevastate <file.apk> --resources /path/to/resources
```

### Resource directory layout

```
resources/
├── apktool.jar          # apktool all-in-one JAR
├── apksigner.jar        # apksigner JAR (Android build-tools)
├── aapt                 # aapt binary (Android build-tools)
├── jadx                 # jadx binary (optional, for encrypted APKs)
└── certifications.json  # trusted organization database
```

### Environment variable

```bash
export APKDEVASTATE_RESOURCES=/opt/apkdevastate/resources
./apkdevastate target.apk
```

---

## certifications.json format

```json
{
  "trustedOrganizations": {
    "google": ["google", "google llc", "android"],
    "samsung": ["samsung", "samsung electronics"]
  }
}
```

Add any organization whose certificate you want to trust as *CLEAN*.

---

## Exit codes

| Code | Meaning |
|---|---|
| `0` | CLEAN verdict |
| `1` | Any other verdict (MALICIOUS, SUSPICIOUS, etc.) |

This lets you integrate with CI/CD:

```bash
apkdevastate app.apk && echo "Safe to deploy" || echo "BLOCKED"
```

---

## Project structure

```
APKdevastate-cli/
├── CMakeLists.txt
├── build.sh
├── resources/
│   └── certifications.json
├── include/
│   ├── terminal.hpp
│   ├── analyzer.hpp
│   ├── apk_extractor.hpp
│   ├── cert_checker.hpp
│   ├── dynamic_loaders.hpp
│   ├── hasher.hpp
│   ├── native_libs.hpp
│   ├── permissions.hpp
│   ├── process_runner.hpp
│   ├── rat_scanner.hpp
│   └── trusted_orgs.hpp
└── src/
    ├── main.cpp
    ├── analyzer.cpp
    ├── apk_extractor.cpp
    ├── cert_checker.cpp
    ├── dynamic_loaders.cpp
    ├── hasher.cpp
    ├── native_libs.cpp
    ├── permissions.cpp
    ├── process_runner.cpp
    ├── rat_scanner.cpp
    ├── terminal.cpp
    └── trusted_orgs.cpp
```

---

> **Disclaimer**: APKdevastate does not guarantee 100% accuracy. Use at your own discretion.
