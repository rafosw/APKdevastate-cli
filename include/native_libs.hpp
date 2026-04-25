#pragma once
#include <map>
#include <string>
#include <vector>

struct NativeLibResult {
  int total_count = 0;
  std::map<std::string, std::vector<std::string>> by_arch;
  std::vector<std::string> suspicious;
};

NativeLibResult analyze_native_libs(const std::string &temp_path);
