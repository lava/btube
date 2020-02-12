#include <string>
#include <vector>

#include <sqlite3.h>

namespace rtmp_authserver {

struct user {
	std::string name;
	std::string encoded_password;
};


// Manages a SQLite user db at the given path
struct userdb {
	userdb();
	userdb(const userdb&) = delete;
	userdb(userdb&&) = default;
	userdb& operator=(const userdb&) = delete;
	userdb& operator=(userdb&&) = default;
	~userdb();

	// todo - return error code
	bool initialize(const std::string& dbpath);

	// Create user or change password
	// Returns 0 on success.
	int create(const std::string& user, const std::string& encoded_password);

	std::vector<user> bulk_load() const;

private:
	sqlite3* db;
};


} // namespace rtmp_authserver