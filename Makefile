server_sources = src/server.cpp
server_objects = $(subst .cpp,.o,$(server_sources))
server_cppflags = -I3rdparty/
server_libs = -pthread -lboost_program_options -lboost_system -largon2 -lfmt

all: rtmp-authserver

$(server_objects): %.o: %.cpp
	g++ -c $+ $(server_cppflags) $(CXXFLAGS) $(CFLAGS) -o $@

rtmp-authserver: $(server_objects)
	g++ $+ $(LDFLAGS) $(server_libs) -o $@

PREFIX = /usr/local

install:
	cp rtmp-authserver $(DESTDIR)$(PREFIX)/bin
