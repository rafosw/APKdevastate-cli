#include "cert_checker.hpp"
#include "process_runner.hpp"
#include <regex>

std::string get_certificate_info(const std::string &apk_path,
                                 const std::string &apksigner_jar) {
  if (!apksigner_jar.empty()) {
    std::string cmd = "java -jar \"" + apksigner_jar +
                      "\" verify --print-certs \"" + apk_path + "\"";
    std::string output = run_process(cmd, true);

    std::regex re(R"(Signer #1 certificate DN:\s*(.+))");
    std::smatch m;
    if (std::regex_search(output, m, re))
      return m[1].str();
  }

  {
    std::string cmd = "apksigner verify --print-certs \"" + apk_path + "\"";
    std::string output = run_process(cmd, true);

    std::regex re(R"(Signer #1 certificate DN:\s*(.+))");
    std::smatch m;
    if (std::regex_search(output, m, re))
      return m[1].str();
  }

  {
    std::string cmd =
        "unzip -p \"" + apk_path +
        "\" META-INF/*.RSA META-INF/*.DSA META-INF/*.EC 2>/dev/null" +
        " | openssl pkcs7 -inform DER -noout -print_certs 2>/dev/null" +
        " | grep 'subject='";
    std::string output = run_process(cmd, false);
    if (!output.empty()) {
      auto pos = output.find('=');
      if (pos != std::string::npos)
        return output.substr(pos + 1);
    }
  }

  return "Certificate info not found.";
}
