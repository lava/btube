# Simple Authentication Server for nginx-rtmp

To setup a live-streaming server, the most common configuration is
to use the nginx-rtmp module with an RTMP ingress and transcoding
to HLS for consumption by a web viewer.

A common problem with this setup is that the RTMP ingress is
completely unauthenticated, so anyone on the internet can use
the server to upload his own video stream.

The remedy is to use the `on_publish` directive, which will query
a given URL and will accept or deny the stream based on the returned
HTTP status code. However, since neither rtmps nor https are supported
by the rtmp module, usual password-based schemes cannot be used since
all data will be transmitted in plain-text.

This is where this server comes in.

# Usage

There are two configurations, called `shared-secret` and `multi-user` below.

The `shared-secret` configuration is the most simple, intended for servers
used by a small group of persons who know and trust each other. A secret
string is distributed among the group, and everyone can use the secret
to start a stream. Generated stream URLs will change for every stream.

The secret in this configuration is only intended to keep random people
from the internet from abusing the server to host their own video streams.

The `multi-user` configuration is slightly more advanced to set up,
since it involves two rtmp servers setting up a remote relay between
each other.

## Simple configuration (shared-secret)

The server provides two endpoints, `/generate` for users who want
to start their stream and `/verify` for the nginx-rtmp module.

Please look at the [nginx example config](./etc/nginx-simple.conf.example)
for details.

## Advanced configuration (multi-user)

Please look at the [nginx example config](./etc/nginx-advanced.conf.example)
for details.


# Build Dependencies

This program requires the following libraries to be installed:

 * Boost.Filesystem
 * Boost.ProgramOptions
 * Boost.Algorithm
 * fmtlib
 * argon2
