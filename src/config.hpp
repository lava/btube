#pragma once

#include <optional>

#include "crow_all.h"

namespace btube {

struct server_config {
	std::string static_html_path;
    std::string bindaddr;
    uint16_t port;
    unsigned int threads;
    bool tls, multiuser;
};

struct endpoints_config {
    std::string signup_key;
    std::string redirect_url;
    std::string html_path;
    std::string dbpath;
    unsigned int default_expiry;
    bool dev_mode;
};

server_config parse_configuration(int argc, const char* argv[]);

} // namespace btube