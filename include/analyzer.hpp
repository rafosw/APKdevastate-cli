#pragma once
#include "permissions.hpp"
#include <string>
#include <vector>

enum class Verdict {
  CLEAN,
  MALICIOUS,
  MALICIOUS_ENCRYPTED,
  SUSPICIOUS,
  ENCRYPTED_OR_PACKED,
  UNWANTED,
};

struct AnalysisResult {
  Verdict verdict;
  std::string verdict_text;
};

AnalysisResult analyze_apk(const std::vector<std::string> &permissions,
                           const std::string &cert_info, bool is_obfuscated,
                           bool rat_found, int permission_count,
                           const std::string &package_name,
                           bool has_jadx_result,
                           const std::string &trusted_orgs_json_path);
