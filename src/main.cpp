#include "analyzer.hpp"
#include "apk_extractor.hpp"
#include "cert_checker.hpp"
#include "dynamic_loaders.hpp"
#include "hasher.hpp"
#include "native_libs.hpp"
#include "permissions.hpp"
#include "process_runner.hpp"
#include "rat_scanner.hpp"
#include "terminal.hpp"
#include <algorithm>
#include <chrono>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <regex>
#include <sstream>
#include <string>
#include <unistd.h>

namespace fs = std::filesystem;

static void print_banner() {
  std::cout << "\n";
  std::cout
      << term::BRED << term::BOLD
      << R"(    ___    ____  __ __     __                     __        __     )"
      << "\n"
      << R"(   /   |  / __ \/ //_/____/ /__ _   ______ ______/ /_____ _/ /____ )"
      << "\n"
      << term::RED
      << R"(  / /| | / /_/ / ,<  / __  / _ \ | / / __ `/ ___/ __/ __ `/ __/ _ \)"
      << "\n"
      << R"( / ___ |/ ____/ /| |/ /_/ /  __/ |/ / /_/ (__  ) /_/ /_/ / /_/  __/)"
      << "\n"
      << term::MAGENTA
      << R"(/_/  |_/_/   /_/ |_|\__,_/\___/|___/\__,_/____/\__/\__,_/\__/\___/ )"
      << term::RESET << "\n"
      << "\n"
      << term::CYAN << term::BOLD
      << "           [ Static APK Malware Analyzer v1.0 CLI ]\n"
      << term::RESET << term::DIM
      << "            Concept & original tool by @rafok2v9c\n"
      << term::RESET << term::DIM
      << " GUI Version for Windows - https://github.com/rafosw/APKdevastate\n"
      << term::RESET << "\n";
}

static void print_separator(const std::string &title = "") {
  const int width = 60;
  std::cout << term::DIM;
  if (title.empty()) {
    for (int i = 0; i < width; ++i)
      std::cout << "\xe2\x94\x80";
  } else {
    int pad = (width - static_cast<int>(title.size()) - 2) / 2;
    for (int i = 0; i < pad; ++i)
      std::cout << "\xe2\x94\x80";
    std::cout << " " << term::RESET << term::BOLD << title << term::RESET
              << term::DIM << " ";
    for (int i = 0; i < pad; ++i)
      std::cout << "\xe2\x94\x80";
  }
  std::cout << term::RESET << "\n";
}

static std::string human_size(uintmax_t bytes) {
  std::ostringstream oss;
  if (bytes < 1024)
    oss << bytes << " B";
  else if (bytes < 1024 * 1024)
    oss << (bytes / 1024.0f) << " KB";
  else
    oss << (bytes / (1024.0f * 1024.0f)) << " MB";
  return oss.str();
}

static std::string find_resources_dir(const std::string &argv0) {

  const char *env = std::getenv("APKDEVASTATE_RESOURCES");
  if (env && fs::exists(env))
    return env;

  if (fs::exists("resources"))
    return fs::absolute("resources").string();

  fs::path bin_dir = fs::path(argv0).parent_path();
  if (fs::exists(bin_dir / "resources"))
    return (bin_dir / "resources").string();

  if (fs::exists("/usr/share/apkdevastate"))
    return "/usr/share/apkdevastate";

  return "";
}

static std::string verdict_color(Verdict v) {
  switch (v) {
  case Verdict::CLEAN:
    return term::BGREEN;
  case Verdict::MALICIOUS:
    return term::BRED;
  case Verdict::MALICIOUS_ENCRYPTED:
    return term::BRED;
  case Verdict::SUSPICIOUS:
    return term::BYELLOW;
  case Verdict::ENCRYPTED_OR_PACKED:
    return term::BYELLOW;
  case Verdict::UNWANTED:
    return term::BYELLOW;
  }
  return term::BWHITE;
}

enum class AppMode {
  SCAN,
  HASH,
  MANIFEST,
  PERMISSIONS,
  CERT,
  STRINGS,
  CLASSES,
  INFO
};

static std::string run_apktool(const std::string &apk_path,
                               const std::string &apktool_jar,
                               const std::string &temp_path) {
  std::string cmd;
  if (!apktool_jar.empty() && fs::exists(apktool_jar))
    cmd = "java -jar \"" + apktool_jar + "\" d \"" + apk_path + "\" -o \"" +
          temp_path + "\" -f";
  else
    cmd = "apktool d \"" + apk_path + "\" -o \"" + temp_path + "\" -f";

  return run_process(cmd, true);
}

int main(int argc, char *argv[]) {

  if (argc < 2) {
    print_banner();
    std::cerr << term::BRED << "Usage: " << term::RESET << argv[0]
              << " <file.apk> [--resources <dir>]\n\n";
    return 1;
  }

  std::string apk_path;
  std::string resources_dir;
  AppMode mode = AppMode::SCAN;

  for (int i = 1; i < argc; ++i) {
    std::string arg(argv[i]);
    if (arg == "--resources" && i + 1 < argc)
      resources_dir = argv[++i];
    else if (arg == "--hash" && i + 1 < argc) {
      mode = AppMode::HASH;
      apk_path = argv[++i];
    } else if (arg == "--scan" && i + 1 < argc) {
      mode = AppMode::SCAN;
      apk_path = argv[++i];
    } else if (arg == "--manifest" && i + 1 < argc) {
      mode = AppMode::MANIFEST;
      apk_path = argv[++i];
    } else if (arg == "--permissions" && i + 1 < argc) {
      mode = AppMode::PERMISSIONS;
      apk_path = argv[++i];
    } else if (arg == "--cert" && i + 1 < argc) {
      mode = AppMode::CERT;
      apk_path = argv[++i];
    } else if (arg == "--strings" && i + 1 < argc) {
      mode = AppMode::STRINGS;
      apk_path = argv[++i];
    } else if (arg == "--classes" && i + 1 < argc) {
      mode = AppMode::CLASSES;
      apk_path = argv[++i];
    } else if (arg == "--info" && i + 1 < argc) {
      mode = AppMode::INFO;
      apk_path = argv[++i];
    } else if (arg == "--help" || arg == "-h") {
      print_banner();
      std::cout
          << "Usage: " << argv[0] << " [options] <file.apk>\n\n"
          << "Options:\n"
          << "  --scan <file.apk>         Full scan (default behavior)\n"
          << "  --hash <file.apk>         Only compute hashes "
             "(MD5/SHA1/SHA256)\n"
          << "  --manifest <file.apk>     Extract and print "
             "AndroidManifest.xml\n"
          << "  --permissions <file.apk>  Print application permissions\n"
          << "  --cert <file.apk>         Print certificate/signer "
             "information\n"
          << "  --strings <file.apk>      Dump string resources from APK\n"
          << "  --classes <file.apk>      List all Java class names (smali)\n"
          << "  --info <file.apk>         Full package info (version, "
             "activities, services)\n"
          << "  --help                    Show this help\n\n";
      return 0;
    } else {
      apk_path = arg;
    }
  }

  if (apk_path.empty()) {
    std::cerr << term::BRED << "[-] " << term::RESET
              << "No APK file specified. Use --help for usage.\n";
    return 1;
  }

  if (!fs::exists(apk_path)) {
    std::cerr << term::BRED << "[-] " << term::RESET
              << "File not found: " << apk_path << "\n";
    return 1;
  }

  if (resources_dir.empty()) {
    resources_dir = find_resources_dir(argv[0]);
    if (resources_dir.empty()) {
      resources_dir = "resources";
    }
  }

  std::string apktool_jar = resources_dir + "/apktool.jar";
  std::string apksigner_jar = resources_dir + "/apksigner.jar";
  std::string aapt_bin = resources_dir + "/aapt";
  std::string jadx_bin = resources_dir + "/jadx";
  std::string certs_json = resources_dir + "/certifications.json";

  bool missing_tools = false;
  std::vector<std::string> missing_list;

  if (!fs::exists(apktool_jar)) {
    missing_tools = true;
    missing_list.push_back("apktool.jar");
  }
  if (!fs::exists(apksigner_jar)) {
    missing_tools = true;
    missing_list.push_back("apksigner.jar");
  }
  if (!fs::exists(aapt_bin)) {
    missing_tools = true;
    missing_list.push_back("aapt");
  }
  if (!fs::exists(jadx_bin)) {
    missing_tools = true;
    missing_list.push_back("jadx");
  }

  if (missing_tools) {
    std::cerr << term::BRED << "[-] " << term::RESET
              << "Missing tools found (in resources directory):\n";
    for (const auto &m : missing_list) {
      std::cerr << "    - " << term::BOLD << m << term::RESET << "\n";
    }
    std::cerr << "\n"
              << term::BYELLOW << "[!] " << term::RESET
              << "Missing tools found. Auto-downloading them into '"
              << resources_dir << "' directory...\n\n";

    fs::create_directories(resources_dir);

    std::string cmd =
        "cd \"" + resources_dir +
        "\" && "
        "echo '\\033[96m[*] Downloading Apktool...\\033[0m' && "
        "wget -q --show-progress "
        "https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.9.3.jar "
        "-O apktool.jar && "
        "echo '\\033[96m[*] Downloading Jadx...\\033[0m' && "
        "wget -q --show-progress "
        "https://github.com/skylot/jadx/releases/download/v1.4.7/"
        "jadx-1.4.7.zip -O jadx.zip && "
        "unzip -q jadx.zip -d jadx_tmp && mv jadx_tmp/bin/jadx . && mv "
        "jadx_tmp/lib . && rm -rf jadx.zip jadx_tmp && "
        "echo '\\033[96m[*] Downloading Android Build Tools (aapt & "
        "apksigner)...\\033[0m' && "
        "wget -q --show-progress "
        "https://dl.google.com/android/repository/"
        "build-tools_r33.0.1-linux.zip -O build-tools.zip && "
        "unzip -q build-tools.zip -d bt_tmp && "
        "mv bt_tmp/android-13/aapt . && "
        "cp bt_tmp/android-13/libc++.so . 2>/dev/null || true && "
        "mv bt_tmp/android-13/lib/apksigner.jar . && "
        "rm -rf build-tools.zip bt_tmp && "
        "chmod +x aapt jadx";

    int res = system(cmd.c_str());
    if (res != 0) {
      std::cerr
          << "\n"
          << term::BRED << "[-] " << term::RESET
          << "Auto-download failed! Please check your internet connection.\n";
      return 1;
    }
    std::cerr << "\n"
              << term::BGREEN << "[+] " << term::RESET
              << "All tools downloaded successfully!\n\n";
  }

  std::string temp_path = "/tmp/apkdevastate_" + std::to_string(::getpid());

  auto aapt_cmd = [&](const std::string &args) -> std::string {
    std::string libpath =
        "LD_LIBRARY_PATH=\"" + resources_dir + ":$LD_LIBRARY_PATH\"";
    std::string cmd = libpath + " \"" + aapt_bin + "\" " + args;
    std::string result = run_process(cmd, true);
    if (result.empty() ||
        result.find("error while loading") != std::string::npos) {
      result = run_process("aapt " + args, true);
    }
    return result;
  };

  print_banner();

  auto t_start = std::chrono::steady_clock::now();

  print_separator("FILE INFO");
  std::string filename = fs::path(apk_path).filename().string();
  uintmax_t file_size = fs::file_size(apk_path);

  std::cout << term::BOLD << "  File : " << term::RESET << filename << "\n";
  std::cout << term::BOLD << "  Path : " << term::RESET
            << fs::absolute(apk_path).string() << "\n";
  std::cout << term::BOLD << "  Size : " << term::RESET << human_size(file_size)
            << "\n\n";

  Hashes hashes;
  PermissionResult perm;
  RatScanResult rat;
  std::string cert_info;
  NativeLibResult native;
  DynamicLoaderResult dyn;

  if (mode == AppMode::HASH || mode == AppMode::SCAN) {
    if (mode == AppMode::SCAN)
      print_separator("HASHES");
    term::progress("Computing hashes", 0);
    try {
      hashes = compute_hashes(apk_path);
      term::progress("Computing hashes", 100);
      std::cout << term::BOLD << "  MD5    " << term::RESET << term::DIM
                << hashes.md5 << term::RESET << "\n";
      std::cout << term::BOLD << "  SHA1   " << term::RESET << term::DIM
                << hashes.sha1 << term::RESET << "\n";
      std::cout << term::BOLD << "  SHA256 " << term::RESET << term::DIM
                << hashes.sha256 << term::RESET << "\n\n";
    } catch (const std::exception &ex) {
      term::error(std::string("Hash computation failed: ") + ex.what());
    }
    if (mode == AppMode::HASH) {
      remove_directory(temp_path);
      return 0;
    }
  }

  if (mode == AppMode::MANIFEST || mode == AppMode::CLASSES) {
    print_separator("EXTRACTION");
    term::info("Running apktool…");
  }
  remove_directory(temp_path);
  run_apktool(apk_path, apktool_jar, temp_path);

  bool manifest_found = fs::exists(temp_path + "/AndroidManifest.xml");
  bool has_jadx_result = !manifest_found;

  if (manifest_found) {
    if (mode == AppMode::MANIFEST) {
      term::ok("AndroidManifest.xml extracted successfully");
      std::ifstream mf(temp_path + "/AndroidManifest.xml");
      std::cout << "\n" << mf.rdbuf() << "\n";
      remove_directory(temp_path);
      return 0;
    }
  } else {
    if (mode == AppMode::MANIFEST) {
      term::error("Failed to extract AndroidManifest.xml");
      remove_directory(temp_path);
      return 1;
    }
    if (mode == AppMode::SCAN) {
      term::warn("AndroidManifest.xml not found – APK may be encrypted/packed");
      term::warn("Deep analysis mode activated (jadx fallback)");

      if (!fs::exists(jadx_bin)) {
        term::error("jadx not found in resources directory!");
        remove_directory(temp_path);
        return 1;
      }

      std::string jadx_out = temp_path + "/jadx_out";
      std::string jadx_cmd =
          "\"" + jadx_bin + "\" -d \"" + jadx_out + "\" \"" + apk_path + "\"";
      term::info("Running jadx…");
      run_process(jadx_cmd, true);

      if (fs::exists(jadx_out))
        term::ok("jadx decompilation completed");
      else
        term::warn("jadx decompilation failed – APK is heavily protected");
    }
  }

  if (mode == AppMode::PERMISSIONS || mode == AppMode::SCAN) {
    if (mode == AppMode::SCAN)
      print_separator("PERMISSIONS");
    term::info("Extracting permissions…");
    std::string aapt_out = aapt_cmd("dump badging \"" + apk_path + "\"");
    perm = parse_permissions(aapt_out, temp_path);

    std::cout << term::BOLD << "  Package   : " << term::RESET
              << perm.package_name << "\n";
    std::cout << term::BOLD << "  SDK Ver   : " << term::RESET
              << perm.sdk_version << "\n";
    std::cout << term::BOLD << "  Perms     : " << term::RESET
              << perm.total_count << " total";
    if (!perm.dangerous_permissions.empty())
      std::cout << "  " << term::BRED << "("
                << perm.dangerous_permissions.size() << " dangerous)"
                << term::RESET;
    std::cout << "\n\n";

    if (!perm.all_permissions.empty()) {
      for (const auto &p : perm.all_permissions) {
        bool dangerous = std::find(perm.dangerous_permissions.begin(),
                                   perm.dangerous_permissions.end(),
                                   p) != perm.dangerous_permissions.end();
        if (dangerous)
          std::cout << "  " << term::BRED << "  [!] " << p << term::RESET
                    << "\n";
        else
          std::cout << "  " << term::DIM << "  [*] " << p << term::RESET
                    << "\n";
      }
    } else {
      std::cout << "  " << term::DIM << "No permissions found\n" << term::RESET;
    }
    std::cout << "\n";

    if (mode == AppMode::PERMISSIONS) {
      remove_directory(temp_path);
      return 0;
    }
  }

  if (mode == AppMode::SCAN) {
    print_separator("RAT SCANNER");
    term::info("Scanning files for known RAT signatures…");
    rat = scan_for_rats(temp_path);

    if (rat.found) {
      std::cout << "\n  " << term::BRED << term::BOLD
                << "[!] KNOWN RAT SIGNATURE DETECTED: " << rat.rat_name
                << term::RESET << "\n\n";
    } else {
      term::ok("No known RAT signatures found");
    }
  }

  if (mode == AppMode::CERT || mode == AppMode::SCAN) {
    if (mode == AppMode::SCAN)
      print_separator("CERTIFICATE");
    term::info("Extracting certificate info via apksigner…");
    cert_info = get_certificate_info(apk_path, apksigner_jar);

    std::cout << "\n  " << term::BOLD << "Signer DN: " << term::RESET
              << term::CYAN << cert_info << term::RESET << "\n\n";

    if (mode == AppMode::CERT) {
      remove_directory(temp_path);
      return 0;
    }
  }

  if (mode == AppMode::STRINGS) {
    print_separator("STRINGS");
    term::info("Dumping string resources via aapt…");
    std::string out = aapt_cmd("dump xmlstrings \"" + apk_path + "\"");

    if (out.empty() || out.find("not found") != std::string::npos ||
        out.find("error") != std::string::npos) {
      term::warn("aapt failed, falling back to basic strings extraction…");
      out = run_process("strings \"" + apk_path + "\"", true);
    }

    if (out.empty()) {
      term::warn("No string resources found.");
    } else {
      std::istringstream ss(out);
      std::string line;
      int count = 0;
      while (std::getline(ss, line)) {
        if (!line.empty()) {
          std::cout << "  " << term::DIM << line << term::RESET << "\n";
          ++count;
        }
      }
      std::cout << "\n"
                << term::BOLD << "  Total: " << term::RESET << count
                << " strings\n\n";
    }
    remove_directory(temp_path);
    return 0;
  }

  if (mode == AppMode::CLASSES) {
    print_separator("JAVA CLASSES");
    term::info("Listing smali classes via apktool…");
    std::error_code ec;
    std::vector<std::string> classes;
    for (const auto &e : fs::recursive_directory_iterator(temp_path, ec)) {
      if (e.is_regular_file() && e.path().extension() == ".smali") {
        std::string rel = fs::relative(e.path(), temp_path, ec).string();
        std::replace(rel.begin(), rel.end(), '/', '.');
        std::replace(rel.begin(), rel.end(), '\\', '.');
        if (rel.size() > 6)
          rel = rel.substr(0, rel.size() - 6);
        classes.push_back(rel);
      }
    }
    std::sort(classes.begin(), classes.end());
    for (const auto &c : classes)
      std::cout << "  " << term::DIM << c << term::RESET << "\n";
    std::cout << "\n"
              << term::BOLD << "  Total: " << term::RESET << classes.size()
              << " classes\n\n";
    remove_directory(temp_path);
    return 0;
  }

  if (mode == AppMode::INFO) {
    print_separator("PACKAGE INFO");
    term::info("Fetching full package info via aapt…");
    std::string raw = aapt_cmd("dump badging \"" + apk_path + "\"");
    auto field = [&](const std::string &label, const std::string &regex_str) {
      std::regex re(regex_str);
      std::smatch m;
      if (std::regex_search(raw, m, re))
        std::cout << "  " << term::BOLD << label << term::RESET << m[1].str()
                  << "\n";
    };
    field("Package     : ", R"(package: name='([^']+)')");
    field("Version     : ", R"(versionName='([^']+)')");
    field("Version Code: ", R"(versionCode='([^']+)')");
    field("Min SDK     : ", R"(sdkVersion:'([^']+)')");
    field("Target SDK  : ", R"(targetSdkVersion:'([^']+)')");
    field("App Label   : ", R"(application-label:'([^']+)')");

    std::cout << "\n  " << term::BOLD << "Activities:\n" << term::RESET;
    std::regex act_re(R"(launchable-activity: name='([^']+)')");
    auto ab = std::sregex_iterator(raw.begin(), raw.end(), act_re);
    auto ae = std::sregex_iterator();
    int ac = 0;
    for (auto it = ab; it != ae; ++it) {
      std::cout << "  " << term::DIM << "  [*] " << (*it)[1].str()
                << term::RESET << "\n";
      ++ac;
    }
    if (ac == 0)
      std::cout << "  " << term::DIM << "  none found\n" << term::RESET;

    std::cout << "\n  " << term::BOLD << "Required Features:\n" << term::RESET;
    std::regex feat_re(R"(uses-feature: name='([^']+)')");
    auto fb = std::sregex_iterator(raw.begin(), raw.end(), feat_re);
    auto fe = std::sregex_iterator();
    int fc = 0;
    for (auto it = fb; it != fe; ++it) {
      std::cout << "  " << term::DIM << "  [*] " << (*it)[1].str()
                << term::RESET << "\n";
      ++fc;
    }
    if (fc == 0)
      std::cout << "  " << term::DIM << "  none found\n" << term::RESET;

    std::cout << "\n";
    remove_directory(temp_path);
    return 0;
  }

  if (mode == AppMode::SCAN) {
    print_separator("NATIVE LIBRARIES (.so)");
    native = analyze_native_libs(temp_path);

    if (native.total_count == 0) {
      std::cout << "  " << term::DIM << "No native libraries found\n"
                << term::RESET;
    } else {
      std::cout << "  " << term::BOLD << "Total: " << term::RESET
                << native.total_count << "  " << term::BOLD
                << "Architectures: " << term::RESET << native.by_arch.size()
                << "\n\n";

      for (const auto &[arch, libs] : native.by_arch) {
        std::cout << "  " << term::BBLUE << "[" << arch << "]" << term::RESET
                  << " - " << libs.size() << " files\n";
        for (const auto &lib : libs) {
          bool susp =
              std::find(native.suspicious.begin(), native.suspicious.end(),
                        lib) != native.suspicious.end();
          if (susp)
            std::cout << "    " << term::BYELLOW << "[!] " << lib << term::RESET
                      << "\n";
          else
            std::cout << "    " << term::DIM << "[*] " << lib << term::RESET
                      << "\n";
        }
        std::cout << "\n";
      }

      if (!native.suspicious.empty()) {
        std::cout << "  " << term::BYELLOW << term::BOLD
                  << "WARNING: " << native.suspicious.size()
                  << " suspicious native libraries detected\n"
                  << term::RESET;
      }
    }
    std::cout << "\n";

    print_separator("DYNAMIC CLASS LOADERS");
    term::info("Scanning smali files for class loader usage…");
    dyn = analyze_dynamic_loaders(temp_path);

    if (dyn.detected_loaders.empty()) {
      term::ok("No dynamic class loaders detected");
      std::cout << "  " << term::DIM << "APK uses standard loading methods\n"
                << term::RESET;
    } else {
      std::cout << "\n  " << term::BYELLOW << term::BOLD
                << dyn.detected_loaders.size()
                << " dynamic loaders detected:" << term::RESET << "\n";
      for (const auto &ld : dyn.detected_loaders)
        std::cout << "    [*] " << ld << "\n";
      if (dyn.is_obfuscated)
        std::cout << "\n  " << term::BYELLOW
                  << "[!] APK appears to be obfuscated or packed "
                     "(long smali file names detected)\n"
                  << term::RESET;
    }
    std::cout << "\n  " << term::DIM << "Scanned " << dyn.scanned_files
              << " smali files\n"
              << term::RESET << "\n";
  }

  bool is_obfuscated = dyn.is_obfuscated;
  if (!is_obfuscated) {
    std::error_code ec;
    for (const auto &e : fs::recursive_directory_iterator(temp_path, ec)) {
      if (e.is_regular_file() && e.path().extension() == ".smali") {
        if (static_cast<int>(e.path().stem().string().size()) > 100) {
          is_obfuscated = true;
          break;
        }
      }
    }
  }

  print_separator("VERDICT");

  AnalysisResult verdict = analyze_apk(
      perm.all_permissions, cert_info, is_obfuscated, rat.found,
      perm.total_count, perm.package_name, has_jadx_result, certs_json);

  auto t_end = std::chrono::steady_clock::now();
  double elapsed = std::chrono::duration<double>(t_end - t_start).count();
  int minutes = static_cast<int>(elapsed) / 60;
  int seconds = static_cast<int>(elapsed) % 60;

  std::cout << "\n";
  std::cout << verdict_color(verdict.verdict) << term::BOLD << "  "
            << verdict.verdict_text << term::RESET << "\n\n";

  print_separator();
  std::cout << term::DIM << "  Analysis completed in " << minutes << "m "
            << seconds << "s"
            << "  |  " << filename << term::RESET << "\n\n";

  auto pad = [](const std::string &s, int w) -> std::string {
    int visible = 0;
    bool in_esc = false;
    for (char c : s) {
      if (c == '\033') {
        in_esc = true;
        continue;
      }
      if (in_esc) {
        if (c == 'm')
          in_esc = false;
        continue;
      }
      ++visible;
    }
    int pad_n = std::max(0, w - visible);
    return s + std::string(static_cast<size_t>(pad_n), ' ');
  };

  auto cv_rat = [&]() -> std::string {
    if (rat.found)
      return std::string(term::BRED) + term::BOLD + "YES - " + rat.rat_name +
             term::RESET;
    return std::string(term::BGREEN) + "No" + term::RESET;
  };
  auto cv_perms = [&]() -> std::string {
    return std::string(term::BYELLOW) +
           std::to_string(perm.dangerous_permissions.size()) + term::RESET +
           " of " + std::to_string(perm.total_count);
  };
  auto cv_obf = [&]() -> std::string {
    if (is_obfuscated)
      return std::string(term::BYELLOW) + "Yes" + term::RESET;
    return std::string(term::DIM) + "No" + term::RESET;
  };

  const int COL = 28;
  std::cout << term::BOLD << "  Quick summary:\n" << term::RESET;
  std::cout
      << "  ┌─────────────────────────────┬────────────────────────────┐\n";
  std::cout << "  │ MD5                         │ "
            << pad(hashes.md5.substr(0, COL), COL) << " │\n";
  std::cout << "  │ RAT detected                │ " << pad(cv_rat(), COL)
            << " │\n";
  std::cout << "  │ Dangerous permissions       │ " << pad(cv_perms(), COL)
            << " │\n";
  std::cout << "  │ Native libs                 │ "
            << pad(std::to_string(native.total_count), COL) << " │\n";
  std::cout << "  │ Dynamic loaders             │ "
            << pad(std::to_string(dyn.detected_loaders.size()), COL) << " │\n";
  std::cout << "  │ Obfuscated/packed           │ " << pad(cv_obf(), COL)
            << " │\n";
  std::cout
      << "  └─────────────────────────────┴────────────────────────────┘\n\n";

  remove_directory(temp_path);

  return (verdict.verdict == Verdict::CLEAN) ? 0 : 1;
}
