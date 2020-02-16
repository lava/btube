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

install:
	@# TODO: Make these paths user-configurable, and then pass them as defines
	@#       to the binaries when compiling.
	mkdir -p $(DESTDIR)$(PREFIX)/bin $(DESTDIR)$(PREFIX)/var/www/btube/static $(DESTDIR)$(PREFIX)/var/run/btube
	install $(installed_binaries) $(DESTDIR)$(PREFIX)/bin
	install -m 644 $(installed_html_templates) $(DESTDIR)$(PREFIX)/var/www/btube/
	install -m 644 $(installed_static_www_resources) $(DESTDIR)$(PREFIX)/var/www/btube/static/
