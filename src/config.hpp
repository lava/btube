#pragma once

#include <optional>

#include "crow_all.h"

namespace rtmp_authserver {

struct server_config {
    std::string bindaddr;
    uint16_t port;
    unsigned int threads;
    bool tls, multiuser;
};

struct endpoints_config {
    std::string signup_key;
    std::string success_template_path;
    std::string redirect_url;
    unsigned int default_expiry;
    bool dev_mode;
};

server_config parse_configuration(int argc, const char* argv[]);

} // namespace rtmp_authserver