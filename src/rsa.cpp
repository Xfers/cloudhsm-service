#include "rsa.h"
#include <openssl/pem.h>
#include <openssl/crypto.h>
#include <stdexcept>
#include <string_view>
#include <iostream>

static std::string base64_encode(const uint8_t *data, size_t size)
{
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, data, size);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);
    std::string ret(bufferPtr->data, bufferPtr->length);
    BIO_free_all(bio);

    return ret;
}

PKey::PKey(const std::string &pem)
    : m_priv(create_private_rsa(pem)), m_privKey(EVP_PKEY_new())
{
    EVP_PKEY_assign_RSA(m_privKey, m_priv);
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

std::string PKey::sign_base64(const uint8_t *data, size_t size) const
{
    auto enc = sign(data, size);
    return base64_encode(enc.data(), enc.size());
}

void PKey::dispose()
{
    EVP_PKEY_free(m_privKey);
}

KeyManager::~KeyManager()
{
    for (auto c : m_map)
    {
        c.second->dispose();
    }
}

void KeyManager::add_key(std::string key, const std::string &pem)
{
    m_map[key] = new PKey(pem);
}