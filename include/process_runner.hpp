#pragma once
#include <string>

std::string run_process(const std::string &command,
                        bool capture_stderr = false);
