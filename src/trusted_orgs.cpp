#include "trusted_orgs.hpp"
#include <fstream>
#include <sstream>

#if __has_include(<nlohmann/json.hpp>)
#include <nlohmann/json.hpp>
#else
#include "nlohmann/json.hpp"
#endif

using json = nlohmann::json;

TrustedOrgsMap load_trusted_orgs(const std::string &json_path) {
  TrustedOrgsMap result;

  std::ifstream ifs(json_path);
  if (!ifs.is_open())
    return result;

  try {
    json doc = json::parse(ifs, nullptr, false);
    if (doc.is_discarded())
      return result;

    auto &orgs = doc["trustedOrganizations"];
    if (!orgs.is_object())
      return result;

    for (auto &[key, val] : orgs.items()) {
      std::vector<std::string> names;
      if (val.is_array()) {
        for (const auto &n : val)
          if (n.is_string())
            names.push_back(n.get<std::string>());
      }
      result[key] = std::move(names);
    }
  } catch (...) {
  }

  return result;
}

std::vector<std::string> flatten_trusted_orgs(const TrustedOrgsMap &m) {
  std::vector<std::string> out;
  for (const auto &[k, v] : m)
    for (const auto &name : v)
      out.push_back(name);
  return out;
}
