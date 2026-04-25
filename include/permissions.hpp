#pragma once
#include <string>
#include <vector>

struct PermissionResult {
  std::string package_name;
  std::string sdk_version;
  std::vector<std::string> all_permissions;
  std::vector<std::string> dangerous_permissions;
  int total_count = 0;
};

PermissionResult parse_permissions(const std::string &aapt_output,
                                   const std::string &temp_path = "");

extern const std::vector<std::string> DANGEROUS_PERMISSION_LIST;
