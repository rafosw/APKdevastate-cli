#include "apk_extractor.hpp"
#include <cerrno>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <vector>
#include <zip.h>

namespace fs = std::filesystem;

bool extract_apk(const std::string &apk_path, const std::string &out_dir) {
  int err = 0;
  zip_t *za = zip_open(apk_path.c_str(), ZIP_RDONLY, &err);
  if (!za) {
    zip_error_t zerr;
    zip_error_init_with_code(&zerr, err);
    zip_error_fini(&zerr);
    return false;
  }

  fs::create_directories(out_dir);

  zip_int64_t n = zip_get_num_entries(za, 0);
  for (zip_int64_t i = 0; i < n; ++i) {
    const char *name = zip_get_name(za, i, 0);
    if (!name)
      continue;

    std::string entry_name(name);
    if (!entry_name.empty() && entry_name.back() == '/') {
      fs::create_directories(out_dir + "/" + entry_name);
      continue;
    }

    fs::path dest = fs::path(out_dir) / entry_name;
    fs::create_directories(dest.parent_path());

    zip_file_t *zf = zip_fopen_index(za, i, 0);
    if (!zf)
      continue;

    std::ofstream out(dest, std::ios::binary);
    if (out.is_open()) {
      std::vector<char> buf(65536);
      zip_int64_t nread;
      while ((nread = zip_fread(zf, buf.data(), buf.size())) > 0)
        out.write(buf.data(), nread);
    }
    zip_fclose(zf);
  }

  zip_close(za);
  return true;
}

void remove_directory(const std::string &path) {
  std::error_code ec;
  fs::remove_all(path, ec);
}
