server_sources = src/server.cpp src/endpoints_multiuser.cpp src/userdb.cpp
server_objects = $(subst .cpp,.o,$(server_sources))
server_cppflags = -I3rdparty/
server_cxxflags = -std=c++17
server_libs = -pthread -lboost_program_options -lboost_filesystem -lboost_system -largon2 -lfmt -lsqlite3

installed_binaries = btube-server
installed_html_templates = $(wildcard src/www/*.html) $(wildcard src/www/*.mustache)
installed_static_www_resources = $(wildcard src/www/static/*)

all: btube-server

$(server_objects): %.o: %.cpp
	g++ -c $+ $(CPPFLAGS) $(server_cppflags) $(server_cxxflags) $(CFLAGS) $(CXXFLAGS) -o $@

btube-server: $(server_objects)
	g++ $+ $(LDFLAGS) $(server_libs) -o $@

clean::
	rm $(server_objects)
	rm btube-server

PREFIX = /usr/local

# TODO: Pass these values as defines when compiling.
# TODO: Allow specifying separate paths for mustache templates and static resources.
bindir = $(DESTDIR)$(PREFIX)/bin
wwwdir = $(DESTDIR)$(PREFIX)/var/www/btube/
datadir = $(DESTDIR)$(PREFIX)/var/run/btube

install:
	@# TODO: Make these paths user-configurable, and then pass them as defines
	@#       to the binaries when compiling.
	mkdir -p  $(bindir) $(wwwdir) $(datadir)
	install $(installed_binaries) $(bindir)
	install -m 644 $(installed_html_templates) $(wwwdir)
	install -m 644 $(installed_static_www_resources) $(wwwdir)/static/

# Convenience install step including extra functionality that would
# usually go in a postinst script.
system_install:
	systemctl stop btube
	$(MAKE) install
	adduser --no-create-home --disabled-password --disabled-login btube
	chown btube:btube $(datadir)
	systemctl start btube