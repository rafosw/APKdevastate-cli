#pragma once
#include <string>

struct RatScanResult {
    bool found = false;
    std::string rat_name;
};

// Scan extracted APK directory for known RAT signatures.
// temp_path should be the directory where apktool has extracted the APK.
RatScanResult scan_for_rats(const std::string& temp_path);
