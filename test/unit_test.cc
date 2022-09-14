#include <gtest/gtest.h>
#include "../src/base64.h"
#include <string>

TEST(HelloTest, base64)
{
    auto decoded = base64_decode(base64_encode((const uint8_t *)"hello", 5));
    EXPECT_STREQ(std::string(decoded.begin(), decoded.end()).c_str(), "hello");
}

std::string to_hex_string(const std::vector<uint8_t> &data) {
    std::string ret;
    static const char *hmap = "0123456789abcdef";
    for(auto &d: data) {
        ret += hmap[(int)d / 16];
        ret += hmap[(int)d % 16];
    }
    return ret;
}

std::vector<uint8_t> hex_to_binary(const std::string &hex) {
    std::vector<uint8_t> ret;

    for(int i=0; i<hex.length(); i+=2) {
        auto h = hex.substr(i, 2);
        ret.push_back(std::stoul(h, nullptr, 16));
    }
    return ret;
}
#include "../src/rsa.h"
TEST(HelloTest, RSA_sign)
{
    auto pkey = PKey::from_file("../test/private-key.pem");

    // echo -n hello | openssl dgst -sign ../test/private-key.pem | xxd -
    const char *ground_truth =
        "c4b560cd3af0df6ae7bc194630aead1e52df93c7fa5f87b4ef57baa9f5aa"
        "5e9c658482ed9efeea44fc01fd7fcd88fdd7ae698e20c7d19b5115e84876"
        "015af522575446044a5d0a4e0531e3457dbd2bbed13181a6ee28e2a74bf2"
        "19ab0aada7719bd565d3d8be819372037dbf30d5d997d3eadc3717849fec"
        "273c659f70cf6db0f0091d6f889b5e12f821d5b2c28faf6f1393a66dde1a"
        "568deacd81a2d247b4ba89a4e46e5939b571df464b365ca1456d829e5a1a"
        "6db57d719ec408d21f4ee31c99739efa87f5051fbdcfb2b0508be5537c0a"
        "7b4de0ac479879c642010f3805b294fc53f4272eed495554b791c46f88bd"
        "2bda36411dd957bab5ef00bec77cf3b5";
    EXPECT_STREQ(ground_truth, to_hex_string(pkey.sign((const uint8_t *)"hello", 5)).c_str());
}

TEST(HelloTest, RSA_pure_sign)
{
    auto pkey = PKey::from_file("../test/private-key.pem");

    // echo -n hello | openssl dgst -sign ../test/private-key.pem | xxd -
    const char *ground_truth =
        "c4b560cd3af0df6ae7bc194630aead1e52df93c7fa5f87b4ef57baa9f5aa"
        "5e9c658482ed9efeea44fc01fd7fcd88fdd7ae698e20c7d19b5115e84876"
        "015af522575446044a5d0a4e0531e3457dbd2bbed13181a6ee28e2a74bf2"
        "19ab0aada7719bd565d3d8be819372037dbf30d5d997d3eadc3717849fec"
        "273c659f70cf6db0f0091d6f889b5e12f821d5b2c28faf6f1393a66dde1a"
        "568deacd81a2d247b4ba89a4e46e5939b571df464b365ca1456d829e5a1a"
        "6db57d719ec408d21f4ee31c99739efa87f5051fbdcfb2b0508be5537c0a"
        "7b4de0ac479879c642010f3805b294fc53f4272eed495554b791c46f88bd"
        "2bda36411dd957bab5ef00bec77cf3b5";

    const char *digest = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
    auto digestb = hex_to_binary(digest);

    EXPECT_STREQ(ground_truth, to_hex_string(pkey.pure_sign(digestb.data(), digestb.size())).c_str());
}