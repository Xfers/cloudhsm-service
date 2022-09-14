#pragma once

#include <openssl/rsa.h>
#include <vector>
#include <string>
#include <memory>
#include <map>

class KeyManager;

class PKey
{
    friend KeyManager;
public:
    // input pem string
    explicit PKey(const std::string &pem);
    PKey(const PKey &rhs) = default;
    ~PKey();

    std::vector<uint8_t> sign(const uint8_t *data, size_t size) const;
    // No digest
    std::vector<uint8_t> pure_sign(const uint8_t *data, size_t size) const;
    static PKey from_file(const std::string &filename);
private:
    void dispose();
    RSA *create_private_rsa(const std::string &pem);
    RSA *m_priv;
    EVP_PKEY *m_privKey;
};

class KeyManager
{
private:
    std::map<std::string, std::shared_ptr<PKey>> m_map;
public:
    KeyManager() = default;
    ~KeyManager();

    // this function is not thread safe
    void add_key(std::string key, const std::string &pem);
    std::shared_ptr<PKey> fetch_key(std::string key) const {
        auto it = m_map.find(key);
        if(it == m_map.end())
            return nullptr;
        return it->second;
    }
    void dispose();
};
