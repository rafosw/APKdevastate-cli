#include "dynamic_loaders.hpp"
#include <algorithm>
#include <atomic>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <thread>
#include <vector>

namespace fs = std::filesystem;

static const std::vector<std::string> LOADER_SIGNATURES = {
    "DexClassLoader",
    "InMemoryDexClassLoader",
    "BaseDexClassLoader",
    "SecureClassLoader",
    "DelegateLastClassLoader",
    "MultiDex",
    "loadDex",
    "defineClass",
    "Ldalvik/system/DexClassLoader",
    "Ldalvik/system/InMemoryDexClassLoader",
    "Ldalvik/system/BaseDexClassLoader",
};

DynamicLoaderResult analyze_dynamic_loaders(const std::string &temp_path) {
  DynamicLoaderResult result;

  std::vector<fs::path> smali_files;
  std::error_code ec;
  for (const auto &entry : fs::recursive_directory_iterator(temp_path, ec)) {
    if (entry.is_regular_file() && entry.path().extension() == ".smali")
      smali_files.push_back(entry.path());
  }

  if (smali_files.empty())
    return result;

  std::mutex mtx;
  std::atomic<int> checked{0};
  std::atomic<bool> should_stop{false};

  unsigned int nthreads = std::max(1u, std::thread::hardware_concurrency());

  auto worker = [&](size_t start, size_t end_idx) {
    for (size_t i = start; i < end_idx && !should_stop.load(); ++i) {
      const auto &path = smali_files[i];

      std::string stem = path.stem().string();
      if (static_cast<int>(stem.size()) > 100) {
        std::lock_guard<std::mutex> lk(mtx);
        result.is_obfuscated = true;
      }

      std::ifstream ifs(path, std::ios::binary);
      if (!ifs.is_open()) {
        ++checked;
        continue;
      }
      std::string content((std::istreambuf_iterator<char>(ifs)),
                          std::istreambuf_iterator<char>());

      for (const auto &sig : LOADER_SIGNATURES) {
        if (content.find(sig) != std::string::npos) {
          std::lock_guard<std::mutex> lk(mtx);
          auto it = std::find(result.detected_loaders.begin(),
                              result.detected_loaders.end(), sig);
          if (it == result.detected_loaders.end())
            result.detected_loaders.push_back(sig);
        }
      }

      int done = ++checked;

      {
        std::lock_guard<std::mutex> lk(mtx);
        if (result.is_obfuscated &&
            static_cast<int>(result.detected_loaders.size()) > 3)
          should_stop = true;
        if (done > 500 && !result.detected_loaders.empty())
          should_stop = true;
      }
    }
  };

  size_t total = smali_files.size();
  size_t chunk = (total + nthreads - 1) / nthreads;
  std::vector<std::thread> threads;
  for (unsigned int t = 0; t < nthreads; ++t) {
    size_t s = t * chunk;
    size_t e = std::min(s + chunk, total);
    if (s < total)
      threads.emplace_back(worker, s, e);
  }
  for (auto &th : threads)
    th.join();

  result.scanned_files = checked.load();
  return result;
}
