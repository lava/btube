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
#include "userdb.hpp"


namespace bpo = boost::program_options;
namespace fs = boost::filesystem;

namespace {

// TODO: implement proper sendfile()-based file transfer for crow,
// e.g. like this: https://github.com/ipkn/crow/issues/116
static void serve_static_file(
    crow::response& rsp,
    const fs::path& filepath,
    const std::string& html_filename,
    bool attachment)
{
    std::ifstream file(filepath.string(), std::ios::binary | std::ios::ate);
    if (!file) {
        rsp.code = 404;
        return rsp.end();
    }

    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);

    std::string buffer(size, 0);
    if (!file.read(buffer.data(), size)) {
        rsp.code = 500;
        return rsp.end(); // "Internal Server Error"
    }

    std::string filename = filepath.filename().string();
    if (filename.find(".mp3") != std::string::npos) {
        rsp.set_header("Content-Type", "audio/mpeg");
    } else if (filename.find(".mkv") != std::string::npos) {
        rsp.set_header("Content-Type", "video/x-matroska");
    } else if (filename.find(".html") != std::string::npos) {
        rsp.set_header("Content-Type", "text/html");
    } else if (filename.find(".js") != std::string::npos) {
        rsp.set_header("Content-Type", "text/javascript");
    } else if (filename.find(".css") != std::string::npos) {
        rsp.set_header("Content-Type", "text/css");
    } else if (filename.find(".svg") != std::string::npos) {
        rsp.set_header("Content-Type", "image/svg+xml");
    } else { // Fallback.
        rsp.set_header("Content-Type", "application/octet-stream");
    }

    if (attachment) {
        if (!html_filename.empty()) {
            rsp.set_header("Content-Disposition", "attachment; filename=\"" + html_filename + "\"");
        } else {
            rsp.set_header("Content-Disposition", "attachment;");
        }
    }

    rsp.body = buffer;
    return rsp.end();
}


static void serve_static_file_from_sandbox(
    crow::response& rsp,
    const fs::path& sandbox,
    const fs::path& subpath,
    bool attachment = true)
{
    // TODO: Not completely sure if this thwarts *all* filename injection attacks,
    // but afaik `filepath` should already be urldecoded and fs::path doesn't
    // have any special escape characters.
    if (boost::algorithm::contains(subpath.string(), "..")
        || subpath.size() == 0
        || subpath.string()[0] == '/') {
        rsp.code = 412; // "Precondition Failed"
        return rsp.end();
    }

    fs::path filepath = sandbox / fs::path(subpath);
    if (!fs::exists(filepath)) {
        rsp.code = 404;
        return rsp.end(); // "File Not Found"
    }

    return serve_static_file(rsp, sandbox / subpath, "", attachment);
}


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

}

void run_server(const btube::server_config& config, btube::http_endpoints endpoints)
{
    crow::SimpleApp app;

    CROW_ROUTE(app, "/").methods("GET"_method)(
        [&](const crow::request& rq) {
            return endpoints.list.get(rq, endpoints.opaque);
        });

    CROW_ROUTE(app, "/list").methods("GET"_method)(
        [&](const crow::request& rq) {
            return endpoints.list.get(rq, endpoints.opaque);
        });

    CROW_ROUTE(app, "/view/<string>").methods("GET"_method)(
        [&](const crow::request& rq, const std::string& streamname) {
            return endpoints.view.get(rq, streamname, endpoints.opaque);
        });

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
            if (addr.rfind("127.0.0.1", 0) == 0) { // if addr starts with 127.0.0.1
                return 200;
            } else {
                return 403;
            }
        });

    CROW_ROUTE(app, "/static/<string>")(
        [&] (const crow::request& rq, crow::response& rsp, const std::string& filename)
        {
            serve_static_file_from_sandbox(rsp, config.static_html_path, filename);
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

void parse_configuration(int argc, char* argv[], btube::server_config& server_config, btube::endpoints_config& endpoints_config)
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
         " Must start with 'rtmp://'.")
        ("html-path", bpo::value<std::string>(&endpoints_config.html_path),
         "Path to html overrides")
        ("mustache-base-path", bpo::value<std::string>(&endpoints_config.mustache_base_path),
         "Base path for includes in .mustache templates.")
        ("userdb", bpo::value<std::string>(&endpoints_config.dbpath),
         "Path to users sqlite database");

    // TODO: Useful options
    //  * http-path-prefix: HTTP path preceding the incoming endpoints (to avoid nginx rewrite rules)
    //  * conf-dir: allow creating a btube.d/ conf directory for proper packaging

    bpo::variables_map vm;
    bpo::store(bpo::parse_command_line(argc, argv, desc), vm);

    if (vm.count("config")) {
        // Can't use `config_filename` because we didn't notify yet.
        std::ifstream configfile(vm["config"].as<std::string>());
        bpo::store(bpo::parse_config_file(configfile, desc), vm);
    }

    bpo::notify(vm);
    // `config` is initialized now

    if (endpoints_config.dev_mode) {
        // Assume the server is running from the build dir in dev mode
        endpoints_config.html_path = "./src/www";
        endpoints_config.mustache_base_path = "./src/www";
        endpoints_config.dbpath = "./users.db";
        server_config.static_html_path = "./src/www/static";
    }

    if (!server_config.tls && (server_config.bindaddr != "localhost" && server_config.bindaddr != "127.0.0.1")) {
        throw std::runtime_error("Plain HTTP only permitted when bound to localhost");
    }
}

int main(int argc, char* argv[])
{
    btube::server_config server_config;
    btube::endpoints_config endpoints_config;
    try {
        parse_configuration(argc, argv, server_config, endpoints_config);
    } catch (boost::program_options::error& e) {
        fmt::fprintf(stderr, "Invalid arguments: %s\n", e.what());
        return 1;
    }

    auto endpoints = btube::make_endpoints_multiuser(endpoints_config);
    run_server(server_config, endpoints);
}
