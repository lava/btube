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

The server provides two endpoints, `/generate` for users who want
to start their stream and `/verify` for the nginx-rtmp module.

Please look at the [./etc/nginx.conf.example](nginx example config)
for details.
