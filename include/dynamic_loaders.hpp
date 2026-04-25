#pragma once
#include <string>
#include <vector>

struct DynamicLoaderResult {
    std::vector<std::string> detected_loaders;
    bool is_obfuscated = false;
    int scanned_files  = 0;
};

// Scan smali files inside the extracted APK for dynamic class loader references.
DynamicLoaderResult analyze_dynamic_loaders(const std::string& temp_path);
