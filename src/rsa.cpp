#include "rsa.h"
#include <openssl/pem.h>
#include <openssl/crypto.h>
#include <stdexcept>
#include <string_view>
#include <iostream>
#include <memory>
#include "base64.h"

PKey::PKey(const std::string &pem)
    : m_priv(create_private_rsa(pem)), m_privKey(EVP_PKEY_new())
{
    EVP_PKEY_assign_RSA(m_privKey, m_priv);
}

PKey::~PKey()
{
    dispose();
}

RSA *PKey::create_private_rsa(const std::string &pem)
{
    RSA *rsa = NULL;
    const char *c_string = pem.c_str();
    BIO *keybio = BIO_new_mem_buf((void *)c_string, -1);
    if (keybio == NULL)
    {
        return 0;
    }
    rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
    BIO_free(keybio);
    return rsa;
}

std::vector<uint8_t> PKey::sign(const uint8_t *data, size_t size) const
{
    EVP_MD_CTX *m_RSASignCtx = EVP_MD_CTX_create();
    if (EVP_DigestSignInit(m_RSASignCtx, NULL, EVP_sha256(), NULL, m_privKey) <= 0)
        throw std::runtime_error("EVP_DigestSignInit");
    if (EVP_DigestSignUpdate(m_RSASignCtx, data, size) <= 0)
        throw std::runtime_error("EVP_DigestSignUpdate");
    size_t msg_len_enc = 0;
    if (EVP_DigestSignFinal(m_RSASignCtx, NULL, &msg_len_enc) <= 0)
        throw std::runtime_error("EVP_DigestSignFinal get length");
    std::vector<uint8_t> enc(msg_len_enc);
    if (EVP_DigestSignFinal(m_RSASignCtx, enc.data(), &msg_len_enc) <= 0)
        throw std::runtime_error("EVP_DigestSignFinal");
    EVP_MD_CTX_free(m_RSASignCtx);
    return enc;
}

std::vector<uint8_t> PKey::pure_sign(const uint8_t *data, size_t size) const
{
    std::shared_ptr<EVP_PKEY_CTX> ctx(EVP_PKEY_CTX_new(m_privKey, nullptr),
        [] (EVP_PKEY_CTX *ctx) { EVP_PKEY_CTX_free(ctx); });

    if (!ctx)
        throw std::runtime_error("EVP_PKEY_CTX_new");

    if (EVP_PKEY_sign_init(ctx.get()) <= 0)
        throw std::runtime_error("EVP_PKEY_sign_init");
    if (EVP_PKEY_CTX_set_rsa_padding(ctx.get(), RSA_PKCS1_PADDING) <= 0)
        throw std::runtime_error("EVP_PKEY_CTX_set_rsa_padding");
    if (EVP_PKEY_CTX_set_signature_md(ctx.get(), EVP_sha256()) <= 0)
        throw std::runtime_error("EVP_PKEY_CTX_set_signature_md");
    size_t msg_len_enc = 0;
    if (EVP_PKEY_sign(ctx.get(), NULL, &msg_len_enc, data, size) <= 0)
        throw std::runtime_error("EVP_PKEY_sign calc length");

    std::vector<uint8_t> enc(msg_len_enc);
    if (EVP_PKEY_sign(ctx.get(), enc.data(), &msg_len_enc, data, size) <= 0)
        throw std::runtime_error("EVP_PKEY_sign calc length");
    return enc;
}

void PKey::dispose()
{
    EVP_PKEY_free(m_privKey);
}

#include <fstream>
static std::string read_file(const std::string &filename)
{
    std::ifstream t(filename);
    return std::string((std::istreambuf_iterator<char>(t)),
                       std::istreambuf_iterator<char>());
}

PKey PKey::from_file(const std::string &filename)
{
    return PKey(read_file(filename));
}

KeyManager::~KeyManager()
{
    dispose();
}

void KeyManager::add_key(std::string key, const std::string &pem)
{
    m_map[key] = std::make_shared<PKey>(pem);
}

void KeyManager::dispose()
{
    m_map.clear();
}
