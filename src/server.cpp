#include <chrono>
#include <random>
#include <unordered_map>
#include <set>

//#include <boost/algorithm/string.hpp>
//#include <boost/algorithm/string/classification.hpp>
#include <boost/program_options.hpp>
#include <boost/filesystem.hpp>

#include "crow_all.h"

namespace bpo = boost::program_options;

typedef std::chrono::system_clock::time_point timepoint;

struct streamkey {
  std::string key;
  timepoint valid_until;
};

std::vector<streamkey> s_streamkeys;
std::mutex s_streamkeys_mutex;

// Values set by configuration

std::string s_psk; // Pre-shared key
std::chrono::minutes s_key_expiry;
uint16_t s_port;
bool s_tls;
std::string s_bindaddr;
bool s_key_reuse;
unsigned int s_threads;

std::string random_string(int n) {
	static thread_local std::mt19937* rng;
	if (!rng) {
		rng = new std::mt19937(clock() + std::hash<std::thread::id>()(std::this_thread::get_id()));
	}

	std::uniform_int_distribution<char> dist(0, 61);
        std::string rs(n, 0);

        for (auto& c : rs) {
                char random = dist(*rng);
                if (random < 26) c = 'a' + random;
                else if (random < 52) c = 'A' + random - 26;
		else c = '0' + random - 52;
        }

        return rs;
}

std::unordered_map<std::string, std::string> parse_url_form(const std::string &data)
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

void cleanup_old_keys(std::vector<streamkey>& v)
{
    auto now = std::chrono::system_clock::now();
    auto end = std::remove_if(v.begin(), v.end(), [&](const streamkey& sk) { return sk.valid_until <= now; });
    v.erase(end, v.end());
}

// https://stackoverflow.com/a/16692519/92560
std::string to_string(const std::chrono::system_clock::time_point &time_point)
{
  const time_t time = std::chrono::system_clock::to_time_t(time_point);
  std::stringstream ss;
#if __GNUC__ > 4 || \
    ((__GNUC__ == 4) && __GNUC_MINOR__ > 8 && __GNUC_REVISION__ > 1)
  // Maybe the put_time will be implemented later?
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

void run_server()
{
    crow::SimpleApp app;

    CROW_ROUTE(app, "/generate").methods("GET"_method)(
        [](const crow::request& rq)
    {
        return R"_(
            <html><head /><body>
              <form action="./generate" method="POST">
                PSK: <input name="secret" type="text" /><br />
                <input type="submit" value="Generate stream key" />
              </form>
            </body></html>)_";
    });

    // Create a new time-limited stream key
    CROW_ROUTE(app, "/generate").methods("POST"_method)(
        [](const crow::request& rq, crow::response& rsp)
    {
        auto params = parse_url_form(rq.body);
        std::string secret = params["secret"];
        if (secret != s_psk) {
            rsp.code = 400;
            rsp.body = "Invalid PSK";
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

        rsp.code = 200;
        rsp.body = "<html><body>"
		   "Your stream key: " + key + "<br />"
		   "Start stream before " + to_string(valid_until) +
		   "</body></html>";
        rsp.end();

    });

    CROW_ROUTE(app, "/verify").methods("POST"_method)(
        [](const crow::request& rq)
    {
	bool valid = false;
        auto params = parse_url_form(rq.body);
        std::string key = params["name"];

	{
		std::lock_guard<std::mutex> lock(s_streamkeys_mutex);
		cleanup_old_keys(s_streamkeys);

		auto it = std::find_if(s_streamkeys.begin(), s_streamkeys.end(), [&](const streamkey& sk) { return sk.key == key; });

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
  uint16_t port;
  unsigned int expiry, threads;
  bool tls, key_reuse;

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
    ("threads", bpo::value<unsigned int>(&threads)->default_value(1),
     "Number of worker threads");

  bpo::variables_map vm;
  bpo::store(bpo::parse_command_line(argc, argv, desc), vm);

  if (vm.count("config")) {
    // Can't use `config_filename` because we didn't notify yet.
    std::ifstream configfile(vm["config"].as<std::string>());
    bpo::store(bpo::parse_config_file(configfile, desc), vm);
  }

  bpo::notify(vm);

  s_psk = secret;
  s_tls = tls;
  s_bindaddr = bindaddr;
  s_port = port;
  s_key_expiry = std::chrono::minutes(expiry);
  s_key_reuse = key_reuse;
  s_threads = threads;

  if (!s_tls && (s_bindaddr != "localhost" && s_bindaddr != "127.0.0.1")) {
    throw std::runtime_error("Plain HTTP only permitted when bound to localhost");
  }
}

int main(int argc, char* argv[])
{
  parse_configuration(argc, argv);
  run_server();
}
