// Copyright (c) 2020 Cesanta Software Limited
// All rights reserved
//
// HTTP server example. This server serves both static and dynamic content.
// It opens two ports: plain HTTP on port 8000 and HTTP on port 8443.
// It implements the following endpoints:
//    /api/stats - respond with free-formatted stats on current connections
//    /api/f2/:id - wildcard example, respond with JSON string {"result": "URI"}
//    any other URI serves static files from s_root_dir
//
// To enable SSL/TLS (using self-signed certificates in PEM files),
//    1. make MBEDTLS_DIR=/path/to/your/mbedtls/installation
//    2. curl -k https://127.0.0.1:8443

#include <cstdint>
#include <vector>
#include <string_view>
#include <string>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include "mongoose.h"
#include "rsa.h"
#include "base64.h"

static const char *s_http_addr = "http://0.0.0.0:8000";   // HTTP port
static const char *s_https_addr = "https://0.0.0.0:8443"; // HTTPS port
static const char *s_root_dir = ".";

KeyManager kmgr;

static std::vector<std::string> split(const std::string &s, char c)
{
    int pos = -1;
    int last = 0;
    std::vector<std::string> ret;
    while ((pos = s.find(c, last)) != std::string::npos)
    {
        ret.push_back(s.substr(last, pos - last));
        last = pos + 1;
    }
    ret.push_back(s.substr(last));
    return ret;
}

// We use the same event handler function for HTTP and HTTPS connections
// fn_data is NULL for plain HTTP, and non-NULL for HTTPS
static void fn(struct mg_connection *c, int ev, void *ev_data, void *fn_data)
{
    if (ev == MG_EV_ACCEPT && fn_data != NULL)
    {
        struct mg_tls_opts opts = {
            //.ca = "ca.pem",         // Uncomment to enable two-way SSL
            .cert = "server.pem",    // Certificate PEM file
            .certkey = "server.pem", // This pem contains both cert and key
        };
        mg_tls_init(c, &opts);
    }
    else if (ev == MG_EV_HTTP_MSG)
    {
        struct mg_http_message *hm = (struct mg_http_message *)ev_data;
        if (mg_http_match_uri(hm, "/api/sign/*") && std::string_view(hm->method.ptr, hm->method.len) == "POST")
        {
            std::string uri(hm->uri.ptr, hm->uri.len);
            auto key = kmgr.fetch_key(split(uri, '/')[3]);
            if (!key)
                mg_http_reply(c, 404, "Content-Type: application/json\r\n", "{message:\"Key not found\"}");
            else
            {

                std::string_view body(hm->body.ptr, hm->body.len);
                std::vector<uint8_t> input(body.cbegin(), body.cend());
                auto result = key->sign(input.data(), input.size());
                std::string base64_result = base64_encode(result.data(), result.size());
                mg_http_reply(c, 200, "Content-Type: application/json\r\n", "{\"result\": \"%s\"}\n", base64_result.c_str());
            }
        }
        else if (mg_http_match_uri(hm, "/api/pure-sign/*") && std::string_view(hm->method.ptr, hm->method.len) == "POST")
        {
            std::string uri(hm->uri.ptr, hm->uri.len);
            auto key = kmgr.fetch_key(split(uri, '/')[3]);
            if (!key)
                mg_http_reply(c, 404, "Content-Type: application/json\r\n", "{message:\"Key not found\"}");
            else
            {
                // TODO: Prevent bad request
                std::string body(hm->body.ptr, hm->body.len);
                auto input_decoded = base64_decode(body);
                auto result = key->pure_sign(input_decoded.data(), input_decoded.size());
                std::string base64_result = base64_encode(result.data(), result.size());
                mg_http_reply(c, 200, "Content-Type: application/json\r\n", "{\"result\": \"%s\"}\n", base64_result.c_str());
            }
        }
        else if (mg_http_match_uri(hm, "/liveness"))
        {
            mg_http_reply(c, 200, "", "OK");
        }
        else
        {
            mg_http_reply(c, 404, "Content-Type: application/json\r\n", "{message:\"Not found\"}");
        }
    }
    (void)fn_data;
}

static int s_signo;
static void signal_handler(int signo)
{
    std::cerr << "Signal received, gracefully shutdown\n";
    s_signo = signo;
}

void start_server()
{

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    struct mg_mgr mgr;                                 // Event manager
    mg_log_set(2);                                     // Set to 3 to enable debug
    mg_mgr_init(&mgr);                                 // Initialise event manager
    mg_http_listen(&mgr, s_http_addr, fn, NULL);       // Create HTTP listener
    mg_http_listen(&mgr, s_https_addr, fn, (void *)1); // HTTPS listener
    while (s_signo == 0)
        mg_mgr_poll(&mgr, 1000); // Infinite event loop
    mg_mgr_free(&mgr);
}

#include <fstream>
#include <streambuf>

static std::string read_file(const std::string &filename)
{
    std::ifstream t(filename);
    return std::string((std::istreambuf_iterator<char>(t)),
                       std::istreambuf_iterator<char>());
}

struct Arguments
{
    bool from_stdin = false;
    std::string input;
    std::map<std::string, std::string> key_files;
} arguments;

std::string get_string(char **&argv)
{
    if (!argv[0])
        throw std::runtime_error("GG");
    std::string ret = *argv;
    argv++;
    return ret;
}

void parse_opts(char *argv[])
{
    while (*argv != nullptr)
    {
        auto entry = get_string(argv);
        if (entry == "-k")
        {
            auto file = get_string(argv);
            arguments.key_files["default"] = file;
        }
        else if (entry == "-m")
        {
            auto pair = get_string(argv);
            auto p = pair.find(":");
            if (p == std::string::npos)
                throw std::runtime_error("GG");
            auto key = pair.substr(0, p);
            auto file_path = pair.substr(p + 1);
            arguments.key_files[key] = file_path;
        }
        else if (entry == "-f")
        {
            arguments.input = read_file(get_string(argv));
        }
        else if (entry == "-s")
        {
            arguments.input = get_string(argv);
        }
        else if (entry == "-")
        {
            arguments.from_stdin = true;
        }
    }
}

#include <openssl/engine.h>

bool try_load_hsm()
{
    ENGINE_load_builtin_engines();
    ENGINE *e = ENGINE_by_id("cloudhsm");
    if (e)
    {
        ENGINE_init(e);
        ENGINE_set_default(e, ENGINE_METHOD_ALL);
        return true;
    }
    else
    {
        return false;
    }
}

#include "base64.h"

int main(int argc, char *argv[])
{
    // auto c = base64_decode(base64_encode((const uint8_t *)"hello", 5));
    // std::cout<<std::string(c.begin(), c.end());
    // return 0;
    if (try_load_hsm())
    {
        std::cerr << "CloudHSM is enabled\n";
    }
    else
    {
        std::cerr << "Failed to load CloudHSM, fall back to software implementation\n";
    }

    if (argc >= 2 && (std::string_view(argv[1]) == "sign" || std::string_view(argv[1]) == "pure-sign"))
    {
        parse_opts(argv);
        PKey key(read_file(arguments.key_files["default"]));

        std::vector<uint8_t> input;
        if (arguments.from_stdin)
        {
            char buf[256];
            std::ostringstream oss;
            oss << std::cin.rdbuf();
            std::string input_string = oss.str();
            input = std::vector<uint8_t>{input_string.cbegin(), input_string.cend()};
        }
        else
        {
            input = std::vector<uint8_t>{arguments.input.cbegin(), arguments.input.cend()};
        }
        std::vector<uint8_t> result;
        if (std::string_view(argv[1]) == "sign")
            result = key.sign(input.data(), input.size());
        else
        {
            // assume input is a binary
            result = key.pure_sign(input.data(), input.size());
        }
        auto result_base64 = base64_encode(result.data(), result.size());
        std::cout << result_base64;
    }
    else if (argc >= 2 && std::string_view(argv[1]) == "server")
    {
        parse_opts(argv);
        for (auto &c : arguments.key_files)
        {
            kmgr.add_key(c.first, read_file(c.second));
        }

        start_server();
    }
    else
    {
        std::cout << "Usage: hsm-service <sign|pure-sign|server> [options]" << std::endl;
    }
    return 0;
}
