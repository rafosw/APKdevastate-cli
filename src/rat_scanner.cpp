#include "rat_scanner.hpp"
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

namespace fs = std::filesystem;

static std::string b64_decode(const std::string &in) {
  static constexpr unsigned char table[256] = {
      64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
      64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
      64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 62, 64, 64, 64, 63,
      52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 64, 64, 64, 64, 64, 64,
      64, 0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14,
      15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 64, 64, 64, 64, 64,
      64, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
      41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 64, 64, 64, 64, 64,
  };
  std::string out;
  out.reserve(in.size() * 3 / 4);
  int val = 0, valb = -8;
  for (unsigned char c : in) {
    if (table[c] == 64)
      break;
    val = (val << 6) + table[c];
    valb += 6;
    if (valb >= 0) {
      out.push_back(static_cast<char>((val >> valb) & 0xFF));
      valb -= 8;
    }
  }
  return out;
}

struct RatSig {
  std::string display_name;
  std::string content_b64;
  std::string filename_b64;
  bool exact_filename = false;
};

static const std::vector<RatSig> RAT_SIGNATURES = {
    {"Metasploit/MSFvenom", "Y29tLm1ldGFzcGxvaXQuc3RhZ2U=", "", false},
    {"SpyNote", "Y2FtZXJhX21hbmFnZXJmeGYweDR4NHgwZnhm", "", false},
    {"SpyNote", "c3B5X25vdGU=", "", false},
    {"CraxsRAT", "c3B5bWF4", "YWNjZXNzZGllY3JpcA==", true},
    {"MASSRAT", "TllBTnhDQVQ=", "", false},
    {"Ahmyth", "YWhteXRoLm1pbmUua2luZy5haG15dGg=", "", false},
    {"DroidJack", "bmV0LmRyb2lkamFjaw==", "", false},
    {"AndroRAT", "QW5kcm9yYXRBY3Rpdml0eQ==", "QW5kcm9pZEFjdGl2aXR5", true},
    {"SpyNote", "c3B5bm90ZQ==", "", false},
    {"SpyMax", "c3B5bWF4", "", false},
    {"CraxsRAT", "Y3JheHNyYXQ=", "", false},
    {"CellikRAT", "Y2VsbGlrcmF0", "", false},
    {"InsomniaSpy", "aW5zb21uaWFzcHk=", "", false},
    {"CypherRAT", "Y3lwaGVycmF0", "", false},
    {"EagleSpy", "ZWFnbGVzcHk=", "", false},
    {"BigSharkRAT", "Ymlnc2hhcmtyYXQ=", "", false},
    {"DroidJack", "ZHJvaWRqYWNr", "", false},
    {"AndroRAT", "YW5kcm9yYXQ=", "", false},
};

static bool read_lower(const fs::path &p, std::string &out) {
  std::ifstream ifs(p, std::ios::binary);
  if (!ifs.is_open())
    return false;
  out.assign((std::istreambuf_iterator<char>(ifs)),
             std::istreambuf_iterator<char>());
  std::transform(out.begin(), out.end(), out.begin(), ::tolower);
  return true;
}

RatScanResult scan_for_rats(const std::string &temp_path) {
  RatScanResult result;

  struct DecodedSig {
    std::string display_name;
    std::string content_kw;
    std::string filename_kw;
    bool exact_filename;
  };
  std::vector<DecodedSig> sigs;
  for (const auto &s : RAT_SIGNATURES) {
    DecodedSig d;
    d.display_name = s.display_name;
    d.exact_filename = s.exact_filename;
    d.content_kw = s.content_b64.empty() ? "" : b64_decode(s.content_b64);
    std::transform(d.content_kw.begin(), d.content_kw.end(),
                   d.content_kw.begin(), ::tolower);
    d.filename_kw = s.filename_b64.empty() ? "" : b64_decode(s.filename_b64);
    std::transform(d.filename_kw.begin(), d.filename_kw.end(),
                   d.filename_kw.begin(), ::tolower);
    sigs.push_back(std::move(d));
  }

  std::error_code ec;
  for (const auto &entry : fs::recursive_directory_iterator(temp_path, ec)) {
    if (!entry.is_regular_file())
      continue;

    std::string stem_lower = entry.path().stem().string();
    std::transform(stem_lower.begin(), stem_lower.end(), stem_lower.begin(),
                   ::tolower);

    std::string content_lower;
    bool content_loaded = false;

    for (const auto &sig : sigs) {
      bool filename_ok = true;
      if (!sig.filename_kw.empty()) {
        if (sig.exact_filename)
          filename_ok = (stem_lower == sig.filename_kw);
        else
          filename_ok = (stem_lower.find(sig.filename_kw) != std::string::npos);
        if (!filename_ok)
          continue;
      }

      if (!sig.content_kw.empty()) {
        if (!content_loaded) {
          if (!read_lower(entry.path(), content_lower))
            break;
          content_loaded = true;
        }
        if (content_lower.find(sig.content_kw) == std::string::npos)
          continue;
      }

      result.found = true;
      result.rat_name = sig.display_name;
      return result;
    }
  }

  return result;
}
