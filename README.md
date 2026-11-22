LuaSec 1.3.2
===============
LuaSec depends  on OpenSSL, and  integrates with LuaSocket to  make it
easy to add secure connections to any Lua applications or scripts.

Documentation: https://github.com/lunarmodules/luasec/wiki

## HTTPS through HTTP proxies

`ssl.https.request` accepts a per-request `proxy = "http://proxy.example:3128"`
or the global `socket.http.PROXY`. This requires matching CONNECT-capable
LuaSocket and LuaSec (`http.PROXY_TUNNEL` and `https.PROXY_TUNNEL`); an old
counterpart produces an explicit error rather than using the wrong protocol.
Both changes are needed: LuaSocket shapes the request and LuaSec opens the tunnel.

Only HTTP proxies are supported, not TLS-to-proxy or SOCKS. The public HTTPS
API rejects non-HTTPS URLs/explicit schemes when a proxy is configured rather
than allowing LuaSocket to downgrade the request to plaintext. URL-encoded Basic
proxy credentials and explicit `Proxy-Authorization` stay on CONNECT and do not
reach the origin; an explicit header takes precedence. Redirect/custom-creator
restrictions in `https.request` remain unchanged. The low-level `https.tcp`
connector accepts `proxy_tunnel = { host, port, user, password, authorization }`
with an origin host/port, already-decoded credentials and optional authorization
header. Its `connect` destination is the proxy; SNI and TLS identity use the origin.

TLS verification defaults are not changed by proxy support. Supply the same
CA/verification parameters you would use for a direct request, e.g. `verify =
"peer", cafile = "/path/to/ca-bundle.pem"`. CONNECT responses are limited to
65536 bytes including line endings; any 2xx status is accepted. Malformed,
rejected, oversized or truncated replies and TCP/TLS failures close the socket.

### Tests

Run the deterministic protocol test from the repository root:

```sh
luajit test/https_proxy_test.lua
```

For real sockets, stage the matching branches of both libraries with their native
modules. Point `LUA_PATH` and `LUA_CPATH` exclusively at that stage (plus Lua's
standard paths), then run:

```sh
LUA_PATH='/path/to/stage/?.lua;;' \
LUA_CPATH='/path/to/stage/?.so;;' python3 test/proxy_integration.py
```

This needs Python 3, OpenSSL's CLI and LuaJIT (`LUA` can select another compatible
Lua interpreter). It creates disposable loopback proxy/TLS servers and certificates,
explicitly enables peer verification, and checks descriptor cleanup. It needs no
external service, network configuration change or account credentials.
