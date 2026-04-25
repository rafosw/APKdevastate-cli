#pragma once
#include <string>

bool extract_apk(const std::string &apk_path, const std::string &out_dir);

void remove_directory(const std::string &path);
