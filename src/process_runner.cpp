#include "process_runner.hpp"
#include <array>
#include <cstdio>
#include <stdexcept>

std::string run_process(const std::string &command, bool capture_stderr) {
  std::string cmd = command;
  if (!capture_stderr)
    cmd += " 2>/dev/null";
  else
    cmd += " 2>&1";

  FILE *pipe = popen(cmd.c_str(), "r");
  if (!pipe)
    return {};

  std::string result;
  std::array<char, 4096> buf{};
  while (fgets(buf.data(), static_cast<int>(buf.size()), pipe) != nullptr)
    result += buf.data();

  pclose(pipe);
  return result;
}
