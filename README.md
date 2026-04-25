# APKdevastate CLI

![Repo Size](https://img.shields.io/github/repo-size/rafosw/APKdevastate)
![Stars](https://img.shields.io/github/stars/rafosw/APKdevastate?style=social)
![Forks](https://img.shields.io/github/forks/rafosw/APKdevastate?style=social)
![Issues](https://img.shields.io/github/issues/rafosw/APKdevastate)

<p align="center">
  <img src="https://github.com/rafosw/APKdevastate/blob/master/ss/fireandroid.gif?raw=true" alt="APKdevastate Banner" width="200"/>
</p>

**APKdevastate CLI** is a powerful Linux C++17 command-line application designed to analyze Android APK files for security risks, malware signatures, and suspicious behaviors. The tool helps identify potentially malicious applications by examining permissions, certificate information, and known Remote Access Trojan (RAT) signatures.

The application may be detected as infected by Anti-Virus because it contains RAT names.

---

## Features

- **Permission Analysis**: Lists and evaluates dangerous Android permissions
- **Certificate Verification**: Validates APK signing certificates against trusted organizations
- **RAT Detection**: Scans for known Remote Access Trojan signatures
- **Hash Generation**: Calculates MD5, SHA1, and SHA256 hashes for file verification
- **Encryption Detection**: Identifies potentially obfuscated or encrypted code
- **Risk Assessment**: Provides an overall security evaluation of the analyzed APK
- **Native Library Scan**: Detects suspicious `.so` libraries
- **Dynamic Loader Check**: Identifies reflection and dynamic class loading

---

## Requirements

### Runtime Tools
- Java Runtime Environment (for apktool & apksigner)
- `apktool`, `aapt`, `apksigner`, `jadx` (Auto-downloaded if missing)

### Build Dependencies
- `cmake` (>= 3.16)
- `g++` (C++17 support)
- `libssl-dev` (OpenSSL)
- `libzip-dev` (libzip)

---

## Installation & Build

Clone the repository and run the build script. The script will automatically download necessary dependencies (like `nlohmann/json` and Android build tools) if they are not found.

```bash
chmod +x build.sh
./build.sh --release
```

---

## Usage

Run the tool from the terminal by providing the path to an APK file.

```bash
./apkdevastate <file.apk>
```

### Options

```bash
  --scan <file.apk>         Full scan (default behavior)
  --hash <file.apk>         Only compute hashes (MD5/SHA1/SHA256)
  --manifest <file.apk>     Extract and print AndroidManifest.xml
  --permissions <file.apk>  Print application permissions
  --cert <file.apk>         Print certificate/signer information
  --strings <file.apk>      Dump string resources from APK
  --classes <file.apk>      List all Java class names (smali)
  --info <file.apk>         Full package info (version, activities, services)
  --help                    Show help menu
```

### Example Usage

```bash
./apkdevastate --scan target_app.apk
```

---

## Support the Project

Love APKdevastate? Give us a star on GitHub!

GUI Version for Windows: [https://github.com/rafosw/APKdevastate](https://github.com/rafosw/APKdevastate)

> **Disclaimer**: APKdevastate does not guarantee 100% accuracy in all detections or results. Use at your own discretion.
