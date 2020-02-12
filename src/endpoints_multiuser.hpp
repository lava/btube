#pragma once

#include <set>
#include <string>
#include <map>
#include <mutex>

#include "userdb.hpp"
#include "mustache.hpp"

//#include "crow_all.h"

// "Private" header for the `multiuser` implementation of the
// http interface.
namespace rtmp_authserver {

typedef std::chrono::system_clock::time_point timepoint;

struct livestream {
    std::string key;
    std::string username;
    std::string title;
    bool is_public;
    bool is_live;
    timepoint key_valid_until;
};

// struct user {
//     std::string name;
//     std::string encoded_password; // Includes salt.
// };

bool operator<(const user& lhs, const user& rhs);
bool operator<(const std::string& lhs, const user& rhs);
bool operator<(const user& lhs, const std::string& rhs);

struct html_templates {
    mustache_template signup_get;
    mustache_template signup_post;
    mustache_template signup_error;

    mustache_template login_get;
    mustache_template login_post;
    mustache_template login_error;

    mustache_template generate_get;
    mustache_template generate_post;
    mustache_template generate_error;

    mustache_template list_get;
    mustache_template view_get;
};

struct backend_state {
    std::string signup_key;
    std::string redirect_url;
    bool dev_mode;
    std::chrono::minutes default_expiry;
    userdb db;

    html_templates html;

    std::mutex users_mutex;
    std::set<user, std::less<>> users; // less for heterogenous lookup

    std::mutex session_mutex;
    std::map<std::string, std::string> sessions; // user name -> session cookie

	std::mutex streams_mutex; // Maybe an rwlock would pay off for this one
	std::vector<livestream> streams;
};

} // namespace rtmp_authserver