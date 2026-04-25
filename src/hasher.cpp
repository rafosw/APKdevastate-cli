#include "hasher.hpp"
#include <fstream>
#include <iomanip>
#include <openssl/evp.h>
#include <openssl/opensslv.h>
#include <sstream>
#include <stdexcept>
#include <vector>

namespace {

std::string bytes_to_hex(const unsigned char* data, unsigned int len)
{
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (unsigned int i = 0; i < len; ++i)
        oss << std::setw(2) << static_cast<unsigned int>(data[i]);
    return oss.str();
}

std::string hash_file(const std::string& path, const char* algo_name)
{
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open())
        throw std::runtime_error("Cannot open file: " + path);

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    EVP_MD* algo = EVP_MD_fetch(nullptr, algo_name, nullptr);
    if (!algo)
        throw std::runtime_error(std::string("EVP_MD_fetch failed for: ") + algo_name);
#else
    const EVP_MD* algo = EVP_get_digestbyname(algo_name);
    if (!algo)
        throw std::runtime_error(std::string("EVP_get_digestbyname failed for: ") + algo_name);
#endif

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
        EVP_MD_free(algo);
#endif
        throw std::runtime_error("EVP_MD_CTX_new failed");
    }

    EVP_DigestInit_ex(ctx, algo, nullptr);

    std::vector<char> buf(1024 * 64);
    while (file.read(buf.data(), static_cast<std::streamsize>(buf.size()))
           || file.gcount() > 0)
        EVP_DigestUpdate(ctx, buf.data(), static_cast<size_t>(file.gcount()));

    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int  digest_len = 0;
    EVP_DigestFinal_ex(ctx, digest, &digest_len);
    EVP_MD_CTX_free(ctx);

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    EVP_MD_free(algo);
#endif

    return bytes_to_hex(digest, digest_len);
}

}

Hashes compute_hashes(const std::string& path)
{
    Hashes h;
    h.md5    = hash_file(path, "MD5");
    h.sha1   = hash_file(path, "SHA1");
    h.sha256 = hash_file(path, "SHA256");
    return h;
}
