----------------------------------------------------------------------------
-- LuaSec 1.3.2
--
-- Copyright (C) 2009-2023 PUC-Rio
--
-- Author: Pablo Musa
-- Author: Tomas Guisasola
---------------------------------------------------------------------------

local socket = require("socket")
local ssl    = require("ssl")
local ltn12  = require("ltn12")
local http   = require("socket.http")
local url    = require("socket.url")

local try    = socket.try

--
-- Module
--
local _M = {
  _VERSION   = "1.3.2",
  _COPYRIGHT = "LuaSec 1.3.2 - Copyright (C) 2009-2023 PUC-Rio",
  PORT       = 443,
  TIMEOUT    = 60
}

-- TLS configuration
local cfg = {
  protocol = "any",
  options  = {"all", "no_sslv2", "no_sslv3", "no_tlsv1"},
  verify   = "none",
}

--------------------------------------------------------------------
-- Auxiliar Functions
--------------------------------------------------------------------

-- Insert default HTTPS port.
local function default_https_port(u)
   return url.build(url.parse(u, {port = _M.PORT}))
end

-- Convert an URL to a table according to Luasocket needs.
local function urlstring_totable(url, body, result_table)
   url = {
      url = default_https_port(url),
      method = body and "POST" or "GET",
      sink = ltn12.sink.table(result_table)
   }
   if body then
      url.source = ltn12.source.string(body)
      url.headers = {
         ["content-length"] = #body,
         ["content-type"] = "application/x-www-form-urlencoded",
      }
   end
   return url
end

-- Forward calls to the real connection object.
local function reg(conn)
   local mt = getmetatable(conn.sock).__index
   for name, method in pairs(mt) do
      if type(method) == "function" then
         conn[name] = function (self, ...)
                         return method(self.sock, ...)
                      end
      end
   end
end

-- Send CONNECT without consuming bytes that belong to the TLS stream.
local function connect_proxy(sock, tunnel)
   local host = tostring(tunnel.host or ""):gsub("^%[(.*)%]$", "%1")
   local port = tostring(tunnel.port or "")
   if host == "" or host:find("[%c%s]") or not port:match("^%d+$") then
      return nil, "invalid CONNECT authority"
   end
   local authority = (host:find(":", 1, true) and ("[" .. host .. "]") or host)
      .. ":" .. port
   local request = "CONNECT " .. authority .. " HTTP/1.1\r\n"
      .. "Host: " .. authority .. "\r\n"
   local authorization = tunnel.authorization
   if authorization then
      if type(authorization) ~= "string" or authorization:find("[%c]") then
         return nil, "invalid proxy authorization"
      end
   elseif tunnel.user ~= nil then
      local mime = require("mime")
      authorization = "Basic " .. mime.b64(tunnel.user .. ":" .. (tunnel.password or ""))
   end
   if authorization then
      request = request .. "Proxy-Authorization: " .. authorization .. "\r\n"
   end
   local sent, err = sock:send(request .. "\r\n")
   if not sent then return nil, err end

   -- A byte budget also bounds a single unterminated line. LuaSocket's
   -- historical receive('*l') API cannot impose this limit.
   local remaining = 65536
   local function receiveline()
      local line = {}
      while true do
         if remaining == 0 then return nil, "proxy CONNECT headers too large" end
         local ch, receive_error = sock:receive(1)
         if not ch then return nil, receive_error end
         remaining = remaining - 1
         if ch == "\n" then return table.concat(line):gsub("\r$", "") end
         line[#line + 1] = ch
      end
   end
   local status
   status, err = receiveline()
   if not status then return nil, err end
   local code = tonumber(status:match("^HTTP/%d%.%d (%d%d%d)%f[%D]"))
   if not code or code < 200 or code >= 300 then
      return nil, "proxy CONNECT failed"
   end
   while true do
      local line
      line, err = receiveline()
      if not line then return nil, err end
      if line == "" then return true end
   end
end

-- Return a function which performs the SSL/TLS connection.
local function tcp(params)
   params = params or {}
   -- Default settings
   for k, v in pairs(cfg) do 
      params[k] = params[k] or v
   end
   -- Force client mode
   params.mode = "client"
   -- 'create' function for LuaSocket
   return function ()
      local conn = {}
      conn.sock = try(socket.tcp())
      function conn:close()
         return self.sock:close()
      end
      local try = socket.newtry(function() conn:close() end)
      local st = getmetatable(conn.sock).__index.settimeout
      function conn:settimeout(...)
         return st(self.sock, _M.TIMEOUT)
      end
      -- Replace TCP's connection function
      function conn:connect(host, port)
         try(self.sock:connect(host, port))
         local tunnel = params.proxy_tunnel
         if tunnel then
            try(connect_proxy(self.sock, tunnel))
         end
         -- LuaSocket replaces params.host with the proxy's TCP address.
         -- TLS identity verification, like SNI, must use the tunnel origin.
         local tlsparams = params
         if tunnel then
            tlsparams = {}
            for k, v in pairs(params) do tlsparams[k] = v end
            tlsparams.host = tunnel.host
         end
         self.sock = try(ssl.wrap(self.sock, tlsparams))
         self.sock:sni(tunnel and tunnel.host or host)
         self.sock:settimeout(_M.TIMEOUT)
         try(self.sock:dohandshake())
         reg(self)
         return 1
      end
      return conn
  end
end

--------------------------------------------------------------------
-- Main Function
--------------------------------------------------------------------

-- Make a HTTP request over secure connection.  This function receives
--  the same parameters of LuaSocket's HTTP module (except 'redirect')
--  plus LuaSec parameters. HTTP proxies use CONNECT.
--
-- @param url mandatory (string or table)
-- @param body optional (string)
-- @return (string if url == string or 1), code, headers, status
--
local function request(url, body)
  local result_table = {}
  local stringrequest = type(url) == "string"
  if stringrequest then
    url = urlstring_totable(url, body, result_table)
  else
    url.url = default_https_port(url.url)
  end
  if url.redirect then
    return nil, "redirect not supported"
  elseif url.create then
    return nil, "create function not permitted"
  end
  if http.PROXY or url.proxy then
    if url.scheme and url.scheme ~= "https"
       or require("socket.url").parse(url.url).scheme ~= "https" then
      return nil, "HTTPS proxy requires an HTTPS URL"
    end
    if not http.PROXY_TUNNEL then
      return nil, "LuaSocket CONNECT support required"
    end
    -- Let LuaSocket classify the proxy and build its tunnel descriptor.
    -- A custom creator would bypass automatic CONNECT classification.
  else
    url.create = tcp(url)
  end
  local res, code, headers, status = http.request(url)
  if res and stringrequest then
    return table.concat(result_table), code, headers, status
  end
  return res, code, headers, status
end

--------------------------------------------------------------------------------
-- Export module
--

_M.request = request
_M.tcp = tcp
_M.PROXY_TUNNEL = true

return _M
