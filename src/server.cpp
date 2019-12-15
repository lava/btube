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

// TODO: Move all output from iostreams to libfmt.
#include <fmt/printf.h>

#include "expected.hpp"
#include "crow_all.h"

namespace bpo = boost::program_options;

typedef std::chrono::system_clock::time_point timepoint;

struct streamkey {
    std::string key;
    timepoint valid_until;
};

std::vector<streamkey> s_streamkeys;
std::mutex s_streamkeys_mutex;

struct user {
    std::string name;
    // The `encoded_password` already includes the salt, so it doesn't
    // need to be stored separately.
    std::string encoded_password;
};

bool operator<(const user& lhs, const user& rhs)
{
    return lhs.name < rhs.name;
}


bool operator<(const std::string& lhs, const user& rhs)
{
    return lhs < rhs.name;
}


bool operator<(const user& lhs, const std::string& rhs)
{
    return lhs.name < rhs;
}

std::set<user, std::less<>> s_users; // less for heterogenous lookup
std::mutex s_users_mutex;

std::map<std::string, std::string> s_user_sessions; // user name -> session cookie
std::mutex s_session_mutex;

// Values set by configuration

std::string s_secret; // Pre-shared key
std::chrono::minutes s_key_expiry;
uint16_t s_port;
bool s_tls;
std::string s_bindaddr;
bool s_key_reuse;
unsigned int s_threads;
crow::mustache::template_t s_success_template("");

// If `s_multiuser` is true, all the variables below must be set.
bool s_multiuser;
std::string redirect_url;

static std::string random_string(int n)
{
        static thread_local std::mt19937* rng;
        if (!rng) {
                auto seed = clock() +
                        std::hash<std::thread::id>()(std::this_thread::get_id());

                rng = new std::mt19937(seed);
        }

        std::uniform_int_distribution<char> dist(0, 61);
        std::string rs(n, 0);

        for (auto& c : rs) {
                char random = dist(*rng);
                if (random < 26)
                        c = 'a' + random;
                else if (random < 52)
                        c = 'A' + random - 26;
                else
                        c = '0' + random - 52;
        }

        return rs;
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


static void cleanup_old_keys(std::vector<streamkey>& v)
{
        auto now = std::chrono::system_clock::now();
        auto end = std::remove_if(v.begin(), v.end(),
                [&](const streamkey& sk) { return sk.valid_until <= now; });

        v.erase(end, v.end());
}


// https://stackoverflow.com/a/16692519
static std::string to_string(
    const std::chrono::system_clock::time_point &time_point)
{
    const time_t time = std::chrono::system_clock::to_time_t(time_point);
    std::stringstream ss;
#if __GNUC__ > 4 || \
        ((__GNUC__ == 4) && __GNUC_MINOR__ > 8 && __GNUC_REVISION__ > 1)
    struct tm tm;
    localtime_r(&time, &tm);
    ss << std::put_time(&tm, "%c"); // Print standard date&time
#else
    char buffer[26];
    ctime_r(&time, buffer);
    buffer[24] = '\0';  // Removes the newline that is added
    ss << buffer;
#endif

    return ss.str();
}


constexpr char NOT_AUTHORIZED[] =
"<html><head></head><body>"
  "You are not authorized to view this content.<br />"
  "<a href=\"/login\">Log in</a> or <a href=\"/signup\">Sign up</a> <br />"
"</body></html>";

static tl::expected<std::string, std::string>
authorize_user(const crow::request& req)
{
    if (!req.headers.count("Cookie")) {
        return tl::unexpected<std::string>("No cookies found.");
    }

    const std::string& cookie_header = req.headers.find("Cookie")->second;
    std::vector<std::string> cookies;
    boost::algorithm::split(cookies, cookie_header, [](char c) {return c == ';' || c == ' ';}, boost::algorithm::token_compress_on);

    std::string session_cookie;
    for (const std::string& cookie_pair : cookies) {
        size_t mid = cookie_pair.find('=');
        if (mid == std::string::npos) {
            return tl::unexpected<std::string>("Invalid cookie header.");
        }

        const std::string& name = cookie_pair.substr(0, mid);
        if (name == "session") {
            session_cookie = cookie_pair.substr(mid+1);
        }
    }

    if (session_cookie.empty()) {
        return tl::unexpected<std::string>("Not logged in.");
    }

    size_t mid = session_cookie.find('_');
    if (mid == std::string::npos) {
        return tl::unexpected<std::string>("Wrong cookie format");
    }

    std::string user = session_cookie.substr(0, mid);
    std::string random = session_cookie.substr(mid+1);
    
    {
        std::lock_guard<std::mutex> lock(s_session_mutex);
        auto it = s_user_sessions.find(user);
        if (it == s_user_sessions.end() || random != it->second) {
            return tl::unexpected<std::string>("Invalid session.");
        }
    }

    return user;
}

#define REQUIRE_AUTHORIZED_USER__2(rq, subject) \
    static_assert(std::is_same<decltype(subject), std::string>::value, \
                  "Subject argument must be of type std::string."); \
    { \
        tl::expected<std::string, std::string> subject_ = authorize_user(rq); \
        if (!subject_) { \
            std::cerr << subject_.error() << '\n'; \
            return crow::response(401, NOT_AUTHORIZED); \
        } \
        subject = subject_.value(); \
    }

#define REQUIRE_AUTHORIZED_USER__3(rq, rsp, subject) \
    static_assert(std::is_same<decltype(subject), std::string>::value, \
                  "Subject argument must be of type std::string."); \
    { \
        tl::expected<std::string, std::string> subject_ = authorize_user(rq); \
        if (!subject_) { \
            std::cerr << subject_.error() << '\n'; \
            rsp.code = 401; \
            rsp.body = NOT_AUTHORIZED; \
            rsp.end(); \
            return; \
        } \
        subject = subject_.value(); \
    }

// Dispatches to one of the two macros above based on the number of arguments.
#define REQUIRE_AUTHORIZED_USER(...) BOOST_PP_OVERLOAD(REQUIRE_AUTHORIZED_USER__,__VA_ARGS__)(__VA_ARGS__)




namespace html_templates {
namespace psk {

crow::mustache::template_t GENERATE = std::string(R"_(
<html>
<head />
<body>
    <form action="./generate" method="POST">
        PSK: <input name="secret" type="text" /><br />
        <input type="submit" value="Generate stream key" />
    </form>
</body>
</html>)_");


crow::mustache::template_t SIGNUP = std::string(R"_(
<html>
<head />
<body>
    Signup not possible; multi-user mode not enabled on this server.
</body>
</html>)_");

crow::mustache::template_t LOGIN = std::string(R"_(
<html>
<head />
<body>
    Signup not possible; multi-user mode not enabled on this server.
</body>
</html>)_");

} // namespace psk


namespace multiuser {

crow::mustache::template_t GENERATE = std::string(R"_(
<html>
<head />
<body>
    <form action="./generate" method="POST">
        Valid for: <input name="valid_for" type="text" /> seconds (enter 0 for a single-use key)<br />
        <input type="submit" value="Generate stream key" />
    </form>
</body>
</html>)_");


crow::mustache::template_t SIGNUP = std::string(R"_(
<html>
<head />
<body>
    <form action="./signup" method="POST">
        Username: <input name="user" type="text" /><br />
        Password: <input name="password" type="text" /><br />
        Sign-up Key: <input name="secret" type="text" /><br />
        <input type="submit" value="Sign up" />
    </form>
</body>
</html>)_");


crow::mustache::template_t LOGIN = std::string(R"_(
<html>
<head />
<body>
    <form action="./login" method="POST">
        Username: <input name="user" type="text" /><br />
        Password: <input name="password" type="text" /><br />
        <input type="submit" value="Log in" />
    </form>
</body>
</html>)_");

} // namespace multiuser
} // namespace html_templates

crow::mustache::template_t DEFAULT_SUCCESS_TEMPLATE = std::string(R"_(
<html>
<body>
    Your stream key: {{key}} <br />
    Start stream before {{valid_until}}
</body>
</html>)_");

// TODO: Use something like this instead of inlining all handlers
// in `run_server()`.
struct authserver_interface {
    // auto signup_get_handler;
    // auto signup_post_handler;
    // auto login_get_handler;
    // auto login_post_handler;
    // auto generate_get_handler;
    // auto generate_post_handler;
    void *opaque;
};


void run_server()
{
    crow::SimpleApp app;

    CROW_ROUTE(app, "/signup").methods("GET"_method)(
        [](const crow::request& rq)
    {
        // TODO: Move this to configuration.
        if (s_multiuser) {
            return html_templates::multiuser::SIGNUP.render();
        } else {
            return html_templates::psk::SIGNUP.render();
        }
    });

    CROW_ROUTE(app, "/signup").methods("POST"_method)(
        [](const crow::request& rq)
    {
        if (!s_multiuser) {
            return crow::response(501, "Cannot sign up; multi-user mode not enabled on this server.");
        }

        auto params = parse_url_form(rq.body);
        std::string secret = params["secret"];
        if (secret != s_secret) {
            return crow::response(403, "Wrong secret.");
        }

        std::string username = params["user"];
        if (username.empty()) {
            return crow::response(400, "Missing 'user' parameter.");
        }

        if (!std::all_of(username.begin(), username.end(), ::isalnum)) {
            return crow::response(400, "Invalid character in 'user': Only alphanumeric characters allowed.");
        }

        std::string password = params["password"];
        if (password.empty()) {
            return crow::response(400, "Missing 'password' parameter.");
        }

        // There's no documentation on the max size of `encoded`,
        // but empirically its 226 bytes for the parameters chosen below. 
        std::string salt(16, '\0');
        std::string encoded(4*128, '\0');

        // It might be better to use random bytes as salt, although I'm
        // not sure if this has any cryptographic basis or if it is just
        // cargo-culting.
        static uint64_t salt_counter = 0;
        ++salt_counter;
        memcpy(&salt[0], &salt_counter, sizeof(salt_counter));

        // NOTE: argon2's parameter situation is pretty weird, with no-one
        // having published any guidance on minimum secure parameters.
        // So the values here (5 iterations, 32MiB memory cost, 1 thread)
        // are pretty much pulled out of thin air.
        // However, unlike scrypt and bcrypt, argon2 actually has a nicely
        // packaged reference implementation with simple-ish API, so we
        // still use it here.
        argon2id_hash_encoded(
            5, 32*1024, 1,                     // Iterations, KiB, Threads
            password.c_str(), password.size(),
            salt.c_str(), salt.size(),
            128,                               // hashlen
            &encoded[0], encoded.size());

        // This seems to survive compiler optimizations up to `-O3`, although
        // I'm not sure that its absolutely required to be preserved by the
        // standard.
        for (int i=0; i<password.size(); ++i) {
            volatile char* c = const_cast<volatile char*>(&password[i]);
            *c = '\0';
        }

        {
            std::lock_guard<std::mutex> lock(s_users_mutex);

            struct user user_ = {username, encoded};

            if (s_users.find(user_) != s_users.end()) {
                return crow::response(400, "Username already taken.");
            }

            s_users.insert(user_);
        }

        // TODO: Redirect to '/login'
        return crow::response(200, "Done.");
    });

    CROW_ROUTE(app, "/login").methods("GET"_method)(
        [](const crow::request& rq)
    {
        if (s_multiuser) {
            return html_templates::multiuser::LOGIN.render();
        } else {
            return html_templates::psk::LOGIN.render();
        }
    });

    CROW_ROUTE(app, "/login").methods("POST"_method)(
        [](const crow::request& rq, crow::response& rsp)
    {
        if (!s_multiuser) {
            rsp.code = 501;
            rsp.body =  "Cannot log in; multi-user mode not enabled on this server.";
            return rsp.end();
        }

        auto params = parse_url_form(rq.body);
        std::string user = params["user"];
        std::string password = params["password"];
        std::string encoded_password;

        {
            std::lock_guard<std::mutex> lock(s_users_mutex);
            auto it = s_users.find(user);
            if (it == s_users.end()) {
                rsp.code = 403;
                rsp.body = "No such user";
                return rsp.end(); // TODO: do we want to do this under mutex?
            }

            encoded_password = it->encoded_password;
        }

        int error = argon2id_verify(encoded_password.c_str(), password.c_str(), password.size());
        if (error != ARGON2_OK) {
            rsp.code = 403;
            rsp.body = "Wrong password";
            rsp.end();
            return;
        }

        std::string random = random_string(64);
        std::string session = user + "_" + random;

        {
            std::lock_guard<std::mutex> lock(s_session_mutex);
            s_user_sessions[user] = random;
        }

        rsp.code = 302;
        rsp.set_header("Set-Cookie", "session=" + session + ";Secure;HttpOnly");
        rsp.set_header("Location", "/generate");
        rsp.body = "<html><head /><body>Logged in as '" + user + "!'</body></html>";
        rsp.end();
        return;
    });

    CROW_ROUTE(app, "/generate").methods("GET"_method)(
        [](const crow::request& rq)
    {
        if (s_multiuser) {
            return html_templates::multiuser::GENERATE.render();
        } else {
            return html_templates::psk::GENERATE.render();
        }
    });

    // Create a new time-limited stream key
    CROW_ROUTE(app, "/generate").methods("POST"_method)(
        [](const crow::request& rq, crow::response& rsp)
    {
        std::string user;
        if (s_multiuser) {
            REQUIRE_AUTHORIZED_USER(rq, rsp, user);
        }

        auto params = parse_url_form(rq.body);
        std::string secret = params["secret"];
        if (secret != s_secret) {
            rsp.code = 400;
            rsp.body = "Wrong secret.";
            rsp.end();
            return;
        }

        std::string key = random_string(25);
        timepoint valid_until = std::chrono::system_clock::now() + s_key_expiry;

        {
            std::lock_guard<std::mutex> lock(s_streamkeys_mutex);
            cleanup_old_keys(s_streamkeys);
            s_streamkeys.push_back(streamkey {key, valid_until});
        }

        crow::mustache::context ctx;
        ctx["key"] = key;
        ctx["valid_until"] = to_string(valid_until);

        rsp.code = 200;
        rsp.body = s_success_template.render(ctx);
        rsp.end();
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

    CROW_ROUTE(app, "/on_play").methods("POST"_method)(
        [](const crow::request& rq)
    {
        // TODO
        return 200;
    });

    CROW_ROUTE(app, "/on_publish").methods("POST"_method)(
        [](const crow::request& rq)
    {
        bool valid = false;
        auto params = parse_url_form(rq.body);
        std::string key = params["name"];

        {
            std::lock_guard<std::mutex> lock(s_streamkeys_mutex);
            cleanup_old_keys(s_streamkeys);

            auto it = std::find_if(s_streamkeys.begin(), s_streamkeys.end(),
                [&](const streamkey& sk) { return sk.key == key; });

            valid = it != s_streamkeys.end();
            if (valid && !s_key_reuse) {
                s_streamkeys.erase(it);
            }
        }

        if (valid) {
            return 200;
        } else {
            return 403;
        }
    });

    if (s_tls) {
        throw std::runtime_error("TLS not supported yet!");
    }

    app
        .port(s_port)
        .bindaddr(s_bindaddr)
        .concurrency(s_threads)
        .run();
}

void parse_configuration(int argc, char* argv[])
{
    std::string secret;
    std::string bindaddr;
    std::string config_filename;
    std::string template_path;
    uint16_t port;
    unsigned int expiry, threads;
    bool tls, key_reuse, multiuser;

    bpo::options_description desc("Options");
    desc.add_options()
        ("config,c", bpo::value<std::string>(&config_filename), "Config file")
        ("secret", bpo::value<std::string>(&secret)->required(), "Pre-shared key")
        ("tls", bpo::value<bool>(&tls)->default_value(false),
         "Use TLS (not supported yet)")
        ("bind", bpo::value<std::string>(&bindaddr)->default_value("127.0.0.1"),
         "Bind ip")
        ("port", bpo::value<uint16_t>(&port)->default_value(3223), "Bind port")
        ("expiry", bpo::value<unsigned int>(&expiry)->default_value(20),
         "Minutes until stream key expires")
        ("key-reuse", bpo::value<bool>(&key_reuse)->default_value(true),
         "Allow using the same stream key multiple times until it expires")
        ("success-template", bpo::value<std::string>(&template_path),
            "Path to mustache template to use after successfully generating streamkey")
        ("threads", bpo::value<unsigned int>(&threads)->default_value(1),
         "Number of worker threads")
        ("multiuser", bpo::value<bool>(&multiuser)->default_value(false),
         "Enable multi-user mode.");

    // TODO: Useful options
    //  * http-path-prefix: HTTP path preceding the incoming endpoints (to avoid nginx rewrite rules)
    //  * 

    bpo::variables_map vm;
    bpo::store(bpo::parse_command_line(argc, argv, desc), vm);

    if (vm.count("config")) {
        // Can't use `config_filename` because we didn't notify yet.
        std::ifstream configfile(vm["config"].as<std::string>());
        bpo::store(bpo::parse_config_file(configfile, desc), vm);
    }

    bpo::notify(vm);

    s_secret = secret;
    s_tls = tls;
    s_bindaddr = bindaddr;
    s_port = port;
    s_key_expiry = std::chrono::minutes(expiry);
    s_key_reuse = key_reuse;
    s_threads = threads;
    s_multiuser = multiuser;

    if (vm.count("success-template")) {
        // https://stackoverflow.com/a/18816228
        std::ifstream ifs(vm["success-template"].as<std::string>(), std::ios::binary | std::ios::ate);
        std::streamsize size = ifs.tellg();
        ifs.seekg(0, std::ios::beg);

        std::string stemplate(size, '\0');
        ifs.read(&stemplate[0], size);
        s_success_template = crow::mustache::template_t(stemplate);
    } else {
        s_success_template = DEFAULT_SUCCESS_TEMPLATE;
    }

    if (s_multiuser) {
        fmt::printf("Warning: Persistent backend storage not yet implemented, all users/passwords will be wiped on restart.\n");
    }

    if (!s_tls && (s_bindaddr != "localhost" && s_bindaddr != "127.0.0.1")) {
        throw std::runtime_error("Plain HTTP only permitted when bound to localhost");
    }
}

int main(int argc, char* argv[])
{
    try {
        parse_configuration(argc, argv);
    } catch (boost::program_options::error& e) {
        fmt::fprintf(stderr, "Invalid arguments: %s\n", e.what());
        return 1;
    }

    run_server();
}
