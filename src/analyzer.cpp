#include "analyzer.hpp"
#include "trusted_orgs.hpp"
#include <algorithm>
#include <regex>

static const std::vector<std::string> UNWANTED_CERT_KW = {"debug",
                                                          "android",
                                                          "hack",
                                                          "android@android.com",
                                                          "test",
                                                          "sample",
                                                          "unknown",
                                                          "null",
                                                          "dev",
                                                          "release",
                                                          "mycompany",
                                                          "certificate",
                                                          "developer",
                                                          "com",
                                                          "default",
                                                          "issuer",
                                                          "root",
                                                          "admin",
                                                          "my name",
                                                          "benim ismim",
                                                          "testkey",
                                                          "company",
                                                          "user",
                                                          "owner",
                                                          "test_cert",
                                                          "testissuer",
                                                          "androiddebugkey",
                                                          "fake",
                                                          "placeholder",
                                                          "temp",
                                                          "keystore",
                                                          "nosign",
                                                          "testsigning",
                                                          "mydebugkey",
                                                          "signingkey",
                                                          "unsigned",
                                                          "example",
                                                          "staging",
                                                          "nobody",
                                                          "me",
                                                          "cert",
                                                          "na",
                                                          "droidjack",
                                                          "androrat"};

static const std::vector<std::string> DANGEROUS_PERMS = {
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.READ_PHONE_STATE",
    "android.permission.CALL_PHONE",
    "android.permission.SYSTEM_ALERT_WINDOW",
};

static std::string to_lower(std::string s) {
  std::transform(s.begin(), s.end(), s.begin(), ::tolower);
  return s;
}

static bool cert_contains_trusted_org(const std::string &cert_lower,
                                      const std::vector<std::string> &orgs) {
  for (const auto &org : orgs) {
    std::string org_lower = to_lower(org);
    std::string escaped;
    for (char c : org_lower) {
      if (std::string("^$.*+?()[]{}|\\").find(c) != std::string::npos)
        escaped += '\\';
      escaped += c;
    }

    for (const std::string field :
         {"\\bo\\s*=\\s*[^,]*", "\\bou\\s*=\\s*[^,]*", "\\bcn\\s*=\\s*[^,]*",
          "\\bl\\s*=\\s*[^,]*"}) {
      std::regex re(field + escaped + "[^,]*", std::regex::icase);
      if (std::regex_search(cert_lower, re))
        return true;
    }

    std::regex re2("\\b" + escaped + "\\b", std::regex::icase);
    if (std::regex_search(cert_lower, re2))
      return true;
  }
  return false;
}

AnalysisResult analyze_apk(const std::vector<std::string> &permissions,
                           const std::string &cert_info, bool is_obfuscated,
                           bool rat_found, int permission_count,
                           const std::string &, bool has_jadx_result,
                           const std::string &trusted_orgs_json_path) {
  auto orgs_map = load_trusted_orgs(trusted_orgs_json_path);
  auto orgs = flatten_trusted_orgs(orgs_map);

  if (rat_found && has_jadx_result) {
    return {Verdict::MALICIOUS_ENCRYPTED,
            "APKdevastate says: MALICIOUS & ENCRYPTED "
            "(This APK is a RAT payload that is also encrypted)"};
  }

  if (rat_found) {
    return {Verdict::MALICIOUS, "APKdevastate says: MALICIOUS "
                                "(This APK is a payload created by a RAT)"};
  }

  std::string cert_lower = to_lower(cert_info);
  bool is_trusted_cert = cert_contains_trusted_org(cert_lower, orgs);

  if (is_trusted_cert) {
    return {Verdict::CLEAN, "APKdevastate says: CLEAN "
                            "(Trusted company certificate detected)"};
  }

  if (permission_count > 15 && !is_trusted_cert) {
    return {Verdict::MALICIOUS,
            "APKdevastate says: MALICIOUS "
            "(Too many permissions requested and no valid certificate found)"};
  }

  int dangerous_count = 0;
  for (const auto &p : permissions) {
    auto it = std::find(DANGEROUS_PERMS.begin(), DANGEROUS_PERMS.end(), p);
    if (it != DANGEROUS_PERMS.end())
      ++dangerous_count;
  }

  bool is_unwanted_cert = false;
  std::vector<std::string> matched_kw;
  for (const auto &kw : UNWANTED_CERT_KW) {
    if (cert_lower.find(kw) != std::string::npos) {
      is_unwanted_cert = true;
      matched_kw.push_back(kw);
    }
  }

  if (dangerous_count > 4 && is_unwanted_cert) {
    std::string kws;
    for (size_t i = 0; i < matched_kw.size() && i < 5; ++i)
      kws += (i ? ", " : "") + matched_kw[i];
    return {Verdict::UNWANTED, "APKdevastate says: UNWANTED "
                               "(Suspicious certificate: " +
                                   kws + " + dangerous permissions)"};
  }

  if (dangerous_count > 3 && !is_trusted_cert) {
    return {Verdict::MALICIOUS,
            "APKdevastate says: MALICIOUS "
            "(No valid certificate found and dangerous permissions detected)"};
  }

  if (is_obfuscated && permission_count > 10) {
    return {Verdict::SUSPICIOUS,
            "APKdevastate says: SUSPICIOUS "
            "(APK is obfuscated/encrypted and requests multiple permissions)"};
  }

  if (has_jadx_result) {
    return {Verdict::ENCRYPTED_OR_PACKED,
            "APKdevastate says: ENCRYPTED or PACKED "
            "(APK is encrypted/packed – potentially unwanted)"};
  }

  return {Verdict::CLEAN, "APKdevastate says: CLEAN "
                          "(No malicious patterns matched by the algorithm)"};
}
