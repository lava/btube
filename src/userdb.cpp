#include "userdb.hpp"

#include <fmt/printf.h>

namespace rtmp_authserver {

userdb::userdb()
  : db(nullptr)
{}

userdb::~userdb()
{
	sqlite3_close(db);
}

bool userdb::initialize(const std::string& dbpath)
{
	if (sqlite3_open_v2(dbpath.c_str(), &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr)) {
		// TODO - print error message provided by sqlite
		fmt::fprintf(stderr, "Couldn't open db at %s\n", dbpath);
		return false;
	}

	char *errmsg;
	if (int result = sqlite3_exec(db,
    	"CREATE TABLE IF NOT EXISTS users("
	    	"id INTEGER PRIMARY KEY ASC AUTOINCREMENT,"
	    	"name TEXT UNIQUE,"
	    	"pwhash TEXT);", nullptr, nullptr, &errmsg); result != SQLITE_OK)
    {
    	fmt::fprintf(stderr, "Couldnt initialize 'users' table: %s\n", errmsg);
    	return false;
    }

    return true;
}


int userdb::create(const std::string& user, const std::string& encoded_password)
{
    sqlite3_stmt *stmt;
    const char *tail;
    int error;
	error = sqlite3_prepare_v2(db,
		"INSERT OR FAIL INTO users (name, pwhash) "
		"VALUES (:name, :pwhash);",
		512, // upper bound for length of sql statement
		&stmt, &tail);

	if (error != SQLITE_OK) {
		fmt::fprintf(stderr, "Error preparing SQL query: %s\n", sqlite3_errmsg(db));
		goto errout;
	}

	error = sqlite3_bind_text(
		stmt,
		sqlite3_bind_parameter_index(stmt, ":pwhash"),
		encoded_password.c_str(),
		-1,             // length up to first null byte
		SQLITE_STATIC); // destructor function for the passed string

	if (error != SQLITE_OK) {
		fmt::fprintf(stderr, "Error binding 'pwhash': %s\n", sqlite3_errmsg(db));
		goto errout;
	}

	sqlite3_bind_text(
		stmt,
		sqlite3_bind_parameter_index(stmt, ":name"),
		user.c_str(),
		-1,              
		SQLITE_STATIC); // destructor function for the passed string

	if (error != SQLITE_OK) {
		fmt::fprintf(stderr, "Error binding 'name': %s\n", sqlite3_errmsg(db));
		goto errout;
	}

	error = sqlite3_step(stmt);
	if (error != SQLITE_DONE) {
		fmt::fprintf(stderr, "Error executing query: %s\n", sqlite3_errmsg(db));
		goto errout;
	}

	return 0;

errout:
	sqlite3_finalize(stmt);
	return error;
}

std::vector<user> userdb::bulk_load() const
{
	std::vector<user> result;
	sqlite3_stmt *stmt;
	const char *tail, *name, *pwhash;
	int error = sqlite3_prepare_v2(db, "SELECT name, pwhash FROM users", 512, &stmt, &tail);
	if (error != SQLITE_OK) {
		fmt::fprintf(stderr, "Error preparing SQL query: ", sqlite3_errmsg(db));
		goto errout;
	}

	while (sqlite3_step(stmt) == SQLITE_ROW) {
		// For some reason, `sqlite3_column_text()` returns `const unsigned char*`.
		name = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
		pwhash = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
		fmt::print("Loaded {}, {}\n", name, pwhash);
		result.push_back(user {name, pwhash});
	}

	// TODO: return error if the last step didnt return eof.

errout:
    sqlite3_finalize(stmt);
    return result;
}

} // namespace rtmp_authserver