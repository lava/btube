#pragma once

#include <memory>

#include "crow_all.h"

#include "config.hpp"

namespace rtmp_authserver {

struct http_handler {
    crow::response (*get)(const crow::request&, void* opaque);
    crow::response (*post)(const crow::request&, void* opaque);
};

struct http_post_handler {
    crow::response (*post)(const crow::request&, void* opaque);
};

// Currently there is only one implementation of this
// interface. This is an interface to external applications
// though (nginx and the rtmp module), so it's better to
// have it well-defined and orderly.
struct http_endpoints {
    // User-facing handlers
    http_handler signup;
    http_handler login;
    http_handler generate;

    // RTMP callback handlers
    http_post_handler on_publish;
    http_post_handler on_play;

    // User-data
    void* opaque;
};


http_endpoints make_endpoints_multiuser(
    const endpoints_config& config);

} // namespace rtmp_authserver
