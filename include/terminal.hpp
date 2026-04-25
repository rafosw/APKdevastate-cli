#pragma once
#include <iostream>
#include <string>

namespace term {

constexpr const char *RESET = "\033[0m";
constexpr const char *BOLD = "\033[1m";
constexpr const char *DIM = "\033[2m";

constexpr const char *RED = "\033[31m";
constexpr const char *GREEN = "\033[32m";
constexpr const char *YELLOW = "\033[33m";
constexpr const char *BLUE = "\033[34m";
constexpr const char *MAGENTA = "\033[35m";
constexpr const char *CYAN = "\033[36m";
constexpr const char *WHITE = "\033[37m";

constexpr const char *BRED = "\033[91m";
constexpr const char *BGREEN = "\033[92m";
constexpr const char *BYELLOW = "\033[93m";
constexpr const char *BBLUE = "\033[94m";
constexpr const char *BMAGENTA = "\033[95m";
constexpr const char *BCYAN = "\033[96m";
constexpr const char *BWHITE = "\033[97m";

inline std::string red(const std::string &s) {
  return std::string(BRED) + s + RESET;
}
inline std::string green(const std::string &s) {
  return std::string(BGREEN) + s + RESET;
}
inline std::string yellow(const std::string &s) {
  return std::string(BYELLOW) + s + RESET;
}
inline std::string cyan(const std::string &s) {
  return std::string(BCYAN) + s + RESET;
}
inline std::string magenta(const std::string &s) {
  return std::string(BMAGENTA) + s + RESET;
}
inline std::string blue(const std::string &s) {
  return std::string(BBLUE) + s + RESET;
}
inline std::string bold(const std::string &s) {
  return std::string(BOLD) + s + RESET;
}
inline std::string dim(const std::string &s) {
  return std::string(DIM) + s + RESET;
}

inline void info(const std::string &msg) {
  std::cout << BCYAN << "[*] " << RESET << msg << "\n";
}
inline void ok(const std::string &msg) {
  std::cout << BGREEN << "[+] " << RESET << msg << "\n";
}
inline void warn(const std::string &msg) {
  std::cout << BYELLOW << "[!] " << RESET << msg << "\n";
}
inline void error(const std::string &msg) {
  std::cout << BRED << "[-] " << RESET << msg << "\n";
}
inline void section(const std::string &msg) {
  std::cout << "\n"
            << BMAGENTA << BOLD << "═══ " << msg << " ═══" << RESET << "\n\n";
}

inline void progress(const std::string &label, int pct) {
  const int width = 40;
  int filled = (pct * width) / 100;
  std::cout << "\r" << BBLUE << label << RESET << " [";
  for (int i = 0; i < width; ++i)
    std::cout << (i < filled ? "█" : "░");
  std::cout << "] " << BYELLOW << pct << "%" << RESET << "   " << std::flush;
  if (pct >= 100)
    std::cout << "\n";
}

} // namespace term