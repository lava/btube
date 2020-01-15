#include <chrono>
#include <random>
#include <unordered_map>
#include <set>
#include <fstream>

#include <argon2.h>

#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/classification.hpp>
#include <boost/filesystem.hpp>
#include <boost/program_options.hpp>

#include <fmt/printf.h>

#include "expected.hpp"
#include "crow_all.h"

#include "config.hpp"
#include "http_endpoints.hpp"


namespace bpo = boost::program_options;


static std::unordered_map<std::string, std::string> parse_url_form(
        const std::string &data)
{
        std::unordered_map<std::string, std::string> result;
 
        std::vector<std::string> params;
        boost::split(params, data, boost::algorithm::is_any_of("&"));
        for (auto param : params) {
                auto split_pos = param.find("=");
                std::string name = param.substr(0, split_pos);
                std::string value = param.substr(split_pos + 1);
                result[name] = value;
        }

        return result;
}


void run_server(const rtmp_authserver::server_config& config, rtmp_authserver::http_endpoints endpoints)
{
    crow::SimpleApp app;

    CROW_ROUTE(app, "/signup").methods("GET"_method)(
        [&](const crow::request& rq) {
            return endpoints.signup.get(rq, endpoints.opaque);
        });

    CROW_ROUTE(app, "/signup").methods("POST"_method)(
        [&](const crow::request& rq) {
            return endpoints.signup.post(rq, endpoints.opaque);
        });

    CROW_ROUTE(app, "/login").methods("GET"_method)(
        [&](const crow::request& rq) {
            return endpoints.login.get(rq, endpoints.opaque);
        });

    CROW_ROUTE(app, "/login").methods("POST"_method)(
        [&](const crow::request& rq) {
            return endpoints.login.post(rq, endpoints.opaque);
        });

    CROW_ROUTE(app, "/generate").methods("GET"_method)(
        [&](const crow::request& rq) {
            return endpoints.generate.get(rq, endpoints.opaque);
        });

    CROW_ROUTE(app, "/generate").methods("POST"_method)(
        [&](const crow::request& rq) {
            return endpoints.generate.post(rq, endpoints.opaque);
        });

    CROW_ROUTE(app, "/on_play").methods("POST"_method)(
        [&](const crow::request& rq) {
            return endpoints.on_play.post(rq, endpoints.opaque);
        });

    CROW_ROUTE(app, "/on_publish").methods("POST"_method)(
        [&](const crow::request& rq) {
            return endpoints.on_publish.post(rq, endpoints.opaque);
        });

    CROW_ROUTE(app, "/reject").methods("POST"_method)(
        [](const crow::request& rq)
    {
        return 403;
    });

    CROW_ROUTE(app, "/allow").methods("POST"_method)(
        [](const crow::request& rq)
    {
        return 200;
    });

    CROW_ROUTE(app, "/allow_local").methods("POST"_method)(
        [](const crow::request& rq)
    {
        // TODO: Doesn't crow already give us the parsed query params?
        auto params = parse_url_form(rq.body);
        std::string name = params["name"];
        std::string app = params["app"];
        std::string addr = params["addr"];
        fmt::print("Incoming maybe local connection from {} to stream {}/{}\n", addr, app, name);
        if (addr.rfind("127.0.0.1", 0) == 0) { // if addr starts with 127.0.0.1
            return 200;
        } else {
            return 403;
        }
    });

    if (config.tls) {
        throw std::runtime_error("TLS not supported yet!");
    }

    app
        .port(config.port)
        .bindaddr(config.bindaddr)
        .concurrency(config.threads)
        .run();
}

void parse_configuration(int argc, char* argv[], rtmp_authserver::server_config& server_config, rtmp_authserver::endpoints_config& endpoints_config)
{
    std::string config_filename;

    // TODO: allow the endpoints implementation to provide their own section of config options.
    bpo::options_description desc("Options");
    desc.add_options()
        ("config,c", bpo::value<std::string>(&config_filename), "Config file")
        ("signup-key", bpo::value<std::string>(&endpoints_config.signup_key)->required(),
         "Signup key") // TODO: allow disabling signups
        ("tls", bpo::value<bool>(&server_config.tls)->default_value(false),
         "Use TLS (not supported yet)")
        ("bind", bpo::value<std::string>(&server_config.bindaddr)->default_value("127.0.0.1"),
         "Bind ip")
        ("port", bpo::value<uint16_t>(&server_config.port)->default_value(3223), "Bind port")
        ("expiry", bpo::value<unsigned int>(&endpoints_config.default_expiry)->default_value(20),
         "Minutes until stream key expires")
        ("threads", bpo::value<unsigned int>(&server_config.threads)->default_value(1),
         "Number of worker threads")
        ("dev-mode", bpo::value<bool>(&endpoints_config.dev_mode)->default_value(false),
         "Allow transporting session cookies over plain HTTP")
        ("redirect-url", bpo::value<std::string>(&endpoints_config.redirect_url),
         "URL of relay rtmp server in multi-user mode."
         " Must start with 'rtmp://'.");

    // TODO: Useful options
    //  * http-path-prefix: HTTP path preceding the incoming endpoints (to avoid nginx rewrite rules)
    //  * ...

    bpo::variables_map vm;
    bpo::store(bpo::parse_command_line(argc, argv, desc), vm);

    if (vm.count("config")) {
        // Can't use `config_filename` because we didn't notify yet.
        std::ifstream configfile(vm["config"].as<std::string>());
        bpo::store(bpo::parse_config_file(configfile, desc), vm);
    }

    bpo::notify(vm);
    // `config` is initialized now

    if (server_config.multiuser) {
        fmt::printf("Warning: Persistent backend storage not yet implemented, all users/passwords will be wiped on restart.\n");
        // TODO - verify that redirect_url starts with 'rtmp://'
        // TODO - verify that redirect_url contains ip literal (no hostname allowed)
    }

    if (!server_config.tls && (server_config.bindaddr != "localhost" && server_config.bindaddr != "127.0.0.1")) {
        throw std::runtime_error("Plain HTTP only permitted when bound to localhost");
    }
}

int main(int argc, char* argv[])
{
    rtmp_authserver::server_config server_config;
    rtmp_authserver::endpoints_config endpoints_config;
    try {
        parse_configuration(argc, argv, server_config, endpoints_config);
    } catch (boost::program_options::error& e) {
        fmt::fprintf(stderr, "Invalid arguments: %s\n", e.what());
        return 1;
    }

    auto endpoints = rtmp_authserver::make_endpoints_multiuser(endpoints_config);
    run_server(server_config, endpoints);
}
