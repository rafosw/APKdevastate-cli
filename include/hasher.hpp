#pragma once
#include <string>

struct Hashes {
  std::string md5;
  std::string sha1;
  std::string sha256;
};

Hashes compute_hashes(const std::string &path);
