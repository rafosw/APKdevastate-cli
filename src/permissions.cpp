#include "permissions.hpp"
#include <algorithm>
#include <fstream>
#include <regex>
#include <sstream>

const std::vector<std::string> DANGEROUS_PERMISSION_LIST = {
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.READ_PHONE_STATE",
    "android.permission.CALL_PHONE",
    "android.permission.SYSTEM_ALERT_WINDOW",
};

PermissionResult parse_permissions(const std::string& aapt_output, const std::string& temp_path)
{
    PermissionResult result;

    {
        std::regex re(R"(package: name='([^']+)')");
        std::smatch m;
        if (std::regex_search(aapt_output, m, re))
            result.package_name = m[1].str();
    }

    {
        std::regex re(R"(sdkVersion:'([^']+)')");
        std::smatch m;
        if (std::regex_search(aapt_output, m, re))
            result.sdk_version = m[1].str();
    }

    {
        std::regex re(R"(uses-permission: name='([^']+)')");
        auto begin = std::sregex_iterator(aapt_output.begin(), aapt_output.end(), re);
        auto end   = std::sregex_iterator();
        for (auto it = begin; it != end; ++it)
            result.all_permissions.push_back((*it)[1].str());
    }

    if (result.all_permissions.empty() && !temp_path.empty()) {
        std::ifstream mf(temp_path + "/AndroidManifest.xml");
        if (mf.is_open()) {
            std::string line;
            std::regex re(R"REGEX(<uses-permission[^>]+android:name="([^"]+)")REGEX");
            while (std::getline(mf, line)) {
                std::smatch m;
                if (std::regex_search(line, m, re))
                    result.all_permissions.push_back(m[1].str());
            }
            std::sort(result.all_permissions.begin(), result.all_permissions.end());
            result.all_permissions.erase(
                std::unique(result.all_permissions.begin(), result.all_permissions.end()),
                result.all_permissions.end());

            if (result.package_name.empty()) {
                mf.clear();
                mf.seekg(0);
                std::string content((std::istreambuf_iterator<char>(mf)),
                                     std::istreambuf_iterator<char>());
                std::regex pkg_re(R"REGEX(package="([^"]+)")REGEX");
                std::smatch pkg_m;
                if (std::regex_search(content, pkg_m, pkg_re))
                    result.package_name = pkg_m[1].str();
            }
        }
    }

    result.total_count = static_cast<int>(result.all_permissions.size());

    for (const auto& p : result.all_permissions) {
        auto found = std::find(DANGEROUS_PERMISSION_LIST.begin(),
                               DANGEROUS_PERMISSION_LIST.end(), p);
        if (found != DANGEROUS_PERMISSION_LIST.end())
            result.dangerous_permissions.push_back(p);
    }

    return result;
}
