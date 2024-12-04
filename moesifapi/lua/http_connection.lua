local _M = {}

local socket = require "socket"
local http = require "resty.http"
-- local Logger = require "logger"
local keepalive_timeout = 600000

local function dump(o)
    if type(o) == 'table' then
      local s = '{ '
      for k,v in pairs(o) do
        if type(k) ~= 'number' then k = '"'..k..'"' end
        s = s .. '['..k..'] = ' .. dump(v) .. ','
      end
      return s .. '} '
    else
      return tostring(o)
    end
  end

function _M.get_client(conf)
    -- Create http client
    return http.new()
end

function _M.get_request(httpc, conf, url_path)

    -- Set a timeout for the request (in milliseconds)
    httpc:set_timeout(conf.connect_timeout)

    return httpc:request_uri(conf.api_endpoint..url_path, {
            method = "GET",
            headers = {
                ["Connection"] = "Keep-Alive",
                ["X-Moesif-Application-Id"] = conf.application_id
            },
            ssl_verify = false -- TODO: Figure it out 
        })
end

function _M.post_request(httpc, conf, url_path, body, isCompressed, user_agent_string)

    local headers = {}
    headers["Connection"] = "Keep-Alive"
    headers["Content-Type"] = "application/json"
    headers["X-Moesif-Application-Id"] = conf.application_id
    headers["User-Agent"] = user_agent_string
    headers["Content-Length"] = #body
    if isCompressed then 
        headers["Content-Encoding"] = "deflate"
    end

    -- Set a timeout for the request (in milliseconds)
    httpc:set_timeout(conf.send_timeout)

    return httpc:request_uri(conf.api_endpoint..url_path, {
        method = "POST",
        body = body,
        headers = headers,
        ssl_verify = false, -- TODO: Figure it out
        keepalive_timeout = keepalive_timeout-- 10min
    })
end

return _M