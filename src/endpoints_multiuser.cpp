#include "http_endpoints.hpp"
#include "endpoints_multiuser.hpp"

#include <random>

#include <argon2.h>

#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/classification.hpp>
#include <boost/filesystem.hpp>

#include <fmt/printf.h>

#include "expected.hpp"

namespace rtmp_authserver {

html_templates load_html(const std::string& html_path);

namespace {

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


static void cleanup_old_keys(std::vector<livestream>& v)
{
        auto now = std::chrono::system_clock::now();
        auto end = std::remove_if(v.begin(), v.end(),
                [&](const livestream& sk) { return sk.key_valid_until <= now; });

        v.erase(end, v.end());
}


static std::string start_session(const std::string& user, backend_state* state)
{
    std::string random = random_string(64);
    std::string session = user + "_" + random;

    {
        // If the user was deleted in the meantime we can end up with a
        // session for a non-existing user here, not sure if that's bad.
        std::lock_guard<std::mutex> lock(state->session_mutex);
        state->sessions[user] = random;
    }

    return session;
}

static tl::expected<std::string, std::string>
authorize_user(const crow::request& req, struct rtmp_authserver::backend_state* state)
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

    // TODO: separate cookie handling and authorization logic.
    bool authorized = false;
    {
        std::lock_guard<std::mutex> lock(state->session_mutex);
        auto it = state->sessions.find(user);
        if (it != state->sessions.end() && random == it->second) {
            authorized = true;
        }
    }

    if (!authorized) {
        return tl::unexpected<std::string>("Invalid session.");
    }

    return user;
}

#define REQUIRE_AUTHORIZED_USER(rq, subject, state, error_template) \
    static_assert(std::is_same<decltype(subject), std::string>::value, \
                  "Subject argument must be of type std::string."); \
    { \
        tl::expected<std::string, std::string> subject_ = authorize_user(rq, state); \
        if (!subject_) { \
            fmt::fprintf(stderr, "%s\n", subject_.error()); \
            crow::mustache::context ctx; \
            ctx["error_code"] = 401; \
            ctx["error_message"] = "You are not authorized to view this page."; \
            return crow::response(401, state->html.error_template.render(ctx)); \
        } \
        subject = subject_.value(); \
    }

} // namespace {




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


crow::response signup_get(const crow::request& rq, void* opaque)
{
    auto* state = static_cast<struct backend_state*>(opaque);
    return state->html.signup_get.render();
}


crow::response signup_post(const crow::request& rq, void* opaque)
{
    auto* state = static_cast<struct backend_state*>(opaque);

    auto make_error = [state] (int code, const char* msg) {
        crow::mustache::context ctx;
        ctx["error_code"] = code;
        ctx["error_message"] = msg;
        return state->html.signup_error.render(ctx);
    };

    auto params = parse_url_form(rq.body);
    std::string secret = params["secret"];
    if (secret != state->signup_key) {
        return make_error(403, "Wrong signup key");
    }

    std::string username = params["user"];
    if (username.empty()) {
        return make_error(400, "Missing 'user' parameter");
    }

    if (!std::all_of(username.begin(), username.end(), ::isalnum)) {
        return make_error(400, "Invalid character in 'user': Only alphanumeric characters allowed");
    }

    std::string password = params["password"];
    if (password.empty()) {
        return make_error(400, "Missing 'password' parameter");
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

    bool success = true;
    {
        std::lock_guard<std::mutex> lock(state->users_mutex);

        struct user user_ = {username, encoded};

        if (state->users.find(user_) != state->users.end()) {
            success = false;
        }

        state->users.insert(user_);
    }

    if (!success) {
        return make_error(400, "Username already taken.");
    }

    state->db.create(username, encoded);

    // TODO: Maybe we should combine this with the locked code block above.
    std::string session = start_session(username, state);

    crow::response rsp;
    if (state->dev_mode) {
        rsp.set_header("Set-Cookie", "session=" + session);
    } else {
        rsp.set_header("Set-Cookie", "session=" + session + ";Secure;HttpOnly");
    }
    crow::mustache::context ctx;
    ctx["user"] = username;
    rsp.body = state->html.signup_post.render(ctx);
    return rsp;
}


crow::response login_get(const crow::request& rq, void* opaque)
{
    auto* state = static_cast<struct backend_state*>(opaque);
    return state->html.login_get.render();
}


crow::response login_post(const crow::request& rq, void* opaque)
{
    auto* state = static_cast<struct backend_state*>(opaque);
    crow::response result;

    auto make_error = [state] (int code, const char* msg) {
        crow::mustache::context ctx;
        ctx["error_code"] = code;
        ctx["error_message"] = msg;
        return state->html.login_error.render(ctx);
    };

    auto params = parse_url_form(rq.body);
    std::string user = params["user"];
    std::string password = params["password"];
    std::string encoded_password;

    bool user_found = true;
    do {
        std::lock_guard<std::mutex> lock(state->users_mutex);
        auto it = state->users.find(user);
        if (it == state->users.end()) {
            user_found = false;
            break;
        }

        encoded_password = it->encoded_password;
    } while (false);

    if (!user_found) {
        return make_error(403, "No such user");     
    }

    int error = argon2id_verify(encoded_password.c_str(), password.c_str(), password.size());
    if (error != ARGON2_OK) {
        return make_error(403, "Wrong password");
    }

    std::string session = start_session(user, state);

    crow::response rsp;
    // TODO: Cookie stuff should probably we part of `start_session()`.
    if (state->dev_mode) {
        rsp.set_header("Set-Cookie", "session=" + session);
    } else {
        rsp.set_header("Set-Cookie", "session=" + session + ";Secure;HttpOnly");
    }
    crow::mustache::context ctx;
    ctx["user"] = user;
    rsp.body = state->html.login_post.render(ctx);
    return rsp;
}


crow::response generate_get(const crow::request& rq, void* opaque)
{
    auto* state = static_cast<struct backend_state*>(opaque);
    std::string user;
    REQUIRE_AUTHORIZED_USER(rq, user, state, generate_error);
    crow::mustache::context ctx;
    ctx["user"] = user;
    return crow::response(200, state->html.generate_get.render(ctx));
}


crow::response generate_post(const crow::request& rq, void* opaque)
{
    auto* state = static_cast<struct backend_state*>(opaque);
    std::string user;
    REQUIRE_AUTHORIZED_USER(rq, user, state, generate_error);

    crow::mustache::context ctx;
    ctx["user"] = user;

    std::string key = random_string(25);

    // TODO: parse actual values from request
    auto params = parse_url_form(rq.body);
    std::string ppublic = params["public"];
    fmt::printf("got param %s\n", ppublic);
    std::string validity = params["validity"];
    char* idx;
    int validity_seconds = std::strtol(validity.c_str(), &idx, 10);
    if ((&validity[0] + validity.size()) != idx) {
        ctx["error_code"] = 400;
        ctx["error_message"] = "Couldn't parse validity as int";
        return crow::response(400, state->html.generate_error.render(ctx));
    }
    std::string title = params["title"];
    bool is_public = params["public"] == "true";
    timepoint valid_until = std::chrono::system_clock::now() + std::chrono::seconds(validity_seconds);
    bool is_live = false;

    {
        std::lock_guard<std::mutex> lock(state->streams_mutex);
        cleanup_old_keys(state->streams);
        state->streams.push_back(livestream {key, user, title, is_public, is_live, valid_until});
    }

    ctx["stream_key"] = key;
    ctx["valid_until"] = to_string(valid_until);
    ctx["title"] = title;
    ctx["public"] = is_public;
    // ctx["rtmp_url"] = ""
    return crow::response(200, state->html.generate_post.render(ctx));
}


crow::response list_get(const crow::request& rq, void* opaque)
{
    auto* state = static_cast<struct backend_state*>(opaque);
    tl::expected<std::string, std::string> user = authorize_user(rq, state);

    std::vector<livestream> streams;
    streams.reserve(24); // Can't know the required size until we lock, but we don't want to do the allocation while locking
    {
        std::lock_guard<std::mutex> lock(state->streams_mutex);
        if (user) {        
            std::copy_if(state->streams.begin(), state->streams.end(), std::back_inserter(streams),
                [](const livestream& stream) { return stream.is_live; });
        } else {
            std::copy_if(state->streams.begin(), state->streams.end(), std::back_inserter(streams),
                [](const livestream& stream) { return stream.is_live && stream.is_public; });
        }
    }

    crow::mustache::context ctx;
    if (user) {
        ctx["user"] = user.value();
    }

    std::vector<crow::mustache::context> stream_contexts;
    stream_contexts.reserve(streams.size());
    for (const auto& stream : streams) {
        crow::mustache::context stream_ctx;
        stream_ctx["name"] = stream.username;
        stream_ctx["title"] = stream.title;
        stream_ctx["public"] = stream.is_public;
        stream_contexts.emplace_back(std::move(stream_ctx));
    }
    ctx["streams"] = std::move(stream_contexts);
    return crow::response(200, state->html.list_get.render(ctx));
}


crow::response view_get(const crow::request& rq, const std::string& streamname, void* opaque)
{
    auto* state = static_cast<struct backend_state*>(opaque);
    tl::expected<std::string, std::string> user = authorize_user(rq, state);
 
    // TODO: do the actual logic here
    livestream stream_info;
    bool valid = false;;
    {
        std::lock_guard<std::mutex> lock(state->streams_mutex);
        auto it = std::find_if(state->streams.begin(), state->streams.end(),
            [&streamname](const livestream& stream) { return stream.username == streamname; });
        if (it != state->streams.end()) {
            valid = true;
            stream_info = *it;
        }
    }

    // Show private streams only to signed-up users.
    if (!user && valid && !stream_info.is_public) {
        valid = false;
    }

    crow::mustache::context ctx;
    if (user) {
        ctx["user"] = user.value();
    }
    crow::mustache::context stream_ctx;
    stream_ctx["name"] = streamname; // TODO: Is this enabling XSS attacks?
    if (valid ) {
        stream_ctx["live"] = stream_info.is_live;
        stream_ctx["public"] = stream_info.is_public;
        stream_ctx["title"] = stream_info.title;
    }
    ctx["stream"] = std::move(stream_ctx);
    return crow::response(200, state->html.view_get.render(ctx));
}


crow::response on_play(const crow::request& rq, void* opaque)
{
    auto params = parse_url_form(rq.body);
    std::string name = params["name"];
    std::string app = params["app"];
    fmt::printf("Permitting playing from %s on app %s\n", name, app);
    return crow::response(200);
}


crow::response on_publish(const crow::request& rq, void* opaque)
{
    auto* state = static_cast<struct backend_state*>(opaque);
    auto params = parse_url_form(rq.body);
    std::string key = params["name"];
    livestream stream_info;
    bool valid;
    {
        std::lock_guard<std::mutex> lock(state->streams_mutex);
        cleanup_old_keys(state->streams);

        auto it = std::find_if(state->streams.begin(), state->streams.end(),
            [&](const livestream& sk) { return sk.key == key; });

        valid = it != state->streams.end();
        if (valid) {
            stream_info = *it; 
        }
    }

    if (!valid) {
        return crow::response(403);
    }

    std::string redirectLocation = fmt::format("{}/{}", state->redirect_url, stream_info.username);

    fmt::printf("Redirecting stream %s to %s\n", key, redirectLocation);

    crow::response rsp;
    rsp.code = 302;
    rsp.set_header("Location", redirectLocation);
    return rsp;
}


void validate_config(const endpoints_config& config)
{
    // TODO - verify that redirect_url starts with 'rtmp://'
    // TODO - verify that redirect_url contains ip literal (no hostname allowed)
}

// TODO: Set this in the build system
#ifndef DEFAULT_HTML_PATH
#define DEFAULT_HTML_PATH "/usr/share/rtmp_authserver/html"
#define DEFAULT_USERDB_PATH "users.db"
#endif

namespace fs = boost::filesystem;

html_templates load_html(const std::string& html_path)
{
    // TODO: Live reload when the path changes on disk.
    fs::path overrides {html_path};
    fs::path defaults {DEFAULT_HTML_PATH};

    html_templates templates;

    std::map<const char*, crow::mustache::template_t*> m {
        {"list.get.html", &templates.list_get },
        {"view.get.html", &templates.view_get },
        {"login.get.html", &templates.login_get },
        {"login.post.html", &templates.login_post },
        {"login.error.html", &templates.login_error },
        {"signup.get.html", &templates.signup_get },
        {"signup.post.html", &templates.signup_post },
        {"signup.error.html", &templates.signup_error },
        {"generate.get.html", &templates.generate_get },
        {"generate.post.html", &templates.generate_post },
        {"generate.error.html", &templates.generate_error },
    };

    for (const auto& kv : m) {
        auto filename = kv.first;
        bool use_override = fs::exists(overrides / filename);
        fs::path path = use_override
            ? overrides / filename
            : defaults / filename;
        // https://stackoverflow.com/a/18816228
        // TODO: There's also a function crow::mustache::load()
        std::ifstream ifs(path.string(), std::ios::binary | std::ios::ate);
        if (!ifs) {
            fmt::fprintf(stderr, "Error opening %s, skipping\n", path.string());
            continue;
        }
        std::streamsize size = ifs.tellg();
        ifs.seekg(0, std::ios::beg);
        std::string data(size, '\0');
        ifs.read(&data[0], size);
        *kv.second = data;
    }

    return templates;
}


http_endpoints make_endpoints_multiuser(
    const endpoints_config& config)
{
    validate_config(config);

    auto* state = new backend_state();
    state->signup_key = config.signup_key;
    state->dev_mode = config.dev_mode;
    state->redirect_url = config.redirect_url;
    state->default_expiry = std::chrono::minutes(config.default_expiry);
    state->html = load_html(config.html_path);

    state->db.initialize(config.dbpath);
    for (auto&& user : state->db.bulk_load()) {
        state->users.insert(user);
    }

    crow::mustache::set_base(config.mustache_base_path);

    http_endpoints endpoints;
    endpoints.opaque = state;

    endpoints.list.get = &list_get;
    endpoints.view.get = &view_get;

    endpoints.signup.get = &signup_get;
    endpoints.signup.post = &signup_post;

    endpoints.login.get = &login_get;
    endpoints.login.post = &login_post;

    endpoints.generate.get = &generate_get;
    endpoints.generate.post = &generate_post;

    endpoints.on_play.post = &on_play;
    endpoints.on_publish.post = &on_publish;

    return endpoints;
}

} // namespace rtmp_authserver