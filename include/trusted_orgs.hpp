#pragma once
#include <map>
#include <string>
#include <vector>

using TrustedOrgsMap = std::map<std::string, std::vector<std::string>>;

TrustedOrgsMap load_trusted_orgs(const std::string &json_path);

std::vector<std::string> flatten_trusted_orgs(const TrustedOrgsMap &m);
