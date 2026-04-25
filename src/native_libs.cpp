#include "native_libs.hpp"
#include <algorithm>
#include <filesystem>

namespace fs = std::filesystem;

static const std::vector<std::string> SUSPICIOUS_KEYWORDS = {
    "encrypt", "obfus", "hook",   "inject",  "hide",  "root",
    "xposed",  "frida", "native", "payload", "shell", "backdoor"};

NativeLibResult analyze_native_libs(const std::string &temp_path) {
  NativeLibResult result;
  fs::path lib_dir = fs::path(temp_path) / "lib";

  if (!fs::exists(lib_dir) || !fs::is_directory(lib_dir))
    return result;

  std::error_code ec;
  for (const auto &arch_entry : fs::directory_iterator(lib_dir, ec)) {
    if (!arch_entry.is_directory())
      continue;
    std::string arch_name = arch_entry.path().filename().string();

    std::vector<std::string> libs_in_arch;
    for (const auto &lib_entry :
         fs::recursive_directory_iterator(arch_entry.path(), ec)) {
      if (!lib_entry.is_regular_file())
        continue;
      if (lib_entry.path().extension() != ".so")
        continue;

      std::string lib_name = lib_entry.path().filename().string();
      libs_in_arch.push_back(lib_name);

      std::string lower_name = lib_name;
      std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(),
                     ::tolower);

      for (const auto &kw : SUSPICIOUS_KEYWORDS) {
        if (lower_name.find(kw) != std::string::npos) {
          auto it = std::find(result.suspicious.begin(),
                              result.suspicious.end(), lib_name);
          if (it == result.suspicious.end())
            result.suspicious.push_back(lib_name);
          break;
        }
      }
    }

    result.by_arch[arch_name] = libs_in_arch;
    result.total_count += static_cast<int>(libs_in_arch.size());
  }

  return result;
}
