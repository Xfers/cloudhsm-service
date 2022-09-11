#include "base64.h"
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/crypto.h>

std::string base64_encode(const uint8_t *data, size_t size)
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

    return ret;
}

std::vector<uint8_t> base64_decode(const std::string &str)
{
    BIO *b64, *bmem;
    BUF_MEM *bufferPtr;
    b64 = BIO_new(BIO_f_base64());
    bmem = BIO_new_mem_buf(str.data(), str.length());

    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    b64 = BIO_push(b64, bmem);

    std::vector<uint8_t> ret(str.length());
    size_t length;
    BIO_read_ex(b64, ret.data(), ret.size(), &length);
    BIO_free_all(b64);

    ret.resize(length);
    // no need
    // ret.shrink_to_fit();

    return ret;
}