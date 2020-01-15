#pragma once

#include <set>
#include <string>
#include <map>
#include <mutex>

// "Private" header for the `multiuser` implementation of the
// http interface.
namespace rtmp_authserver {

typedef std::chrono::system_clock::time_point timepoint;

struct streamkey {
    std::string key;
    std::string username;
    timepoint valid_until;
};


struct user {
    std::string name;
    std::string encoded_password; // Includes salt.
};

bool operator<(const user& lhs, const user& rhs);
bool operator<(const std::string& lhs, const user& rhs);
bool operator<(const user& lhs, const std::string& rhs);

struct backend_state {
    std::string signup_key;
    std::string redirect_url;
    bool dev_mode;
    std::chrono::minutes default_expiry;

    std::mutex users_mutex;
    std::set<user, std::less<>> users; // less for heterogenous lookup

    std::mutex session_mutex;
    std::map<std::string, std::string> sessions; // user name -> session cookie

	std::mutex streamkeys_mutex;
	std::vector<streamkey> streamkeys;
};

} // namespace rtmp_authserver