local _M = {}

local string_format = string.format
local ngx_log = ngx.log
local ngx_log_ERR = ngx.ERR
local cjson = require "cjson"
-- local Logger = require "logger"
-- local zlib = require "zlib"

-- local function compress_data(input_string)
--   local compressor = zlib.deflate()
--   local compressed_data, eof, bytes_in, bytes_out = compressor(input_string, "finish")
--   return compressed_data
-- end


-- function _M.generate_post_payload(config, parsed_url, message, application_id, user_agent_string, debug, timer_start, timer_delay_in_seconds)

--   local payload = nil
--   local body = cjson.encode(message)

--   local ok, compressed_body = pcall(compress_data, body)
--   if not ok then
--     if debug then
--       ngx_log(ngx_log_ERR, "[moesif] USING COMMON FUNCTION failed to compress body: ", compressed_body)
--     end

--     payload = string_format(
--       "%s %s HTTP/1.1\r\nHost: %s\r\nConnection: Keep-Alive\r\nX-Moesif-Pid:" .. tostring(ngx.worker.pid()) .. "\r\nX-Moesif-Timer-Start:" .. tostring(timer_start) .. "\r\nX-Moesif-Timer-Delay:" .. tostring(timer_delay_in_seconds) .. "\r\nX-Moesif-Application-Id: %s\r\nUser-Agent: %s\r\nContent-Type: application/json\r\nContent-Length: %s\r\n\r\n%s",
--       "POST", parsed_url.path, parsed_url.host, application_id, user_agent_string, #body, body)
    
--       ngx_log(ngx_log_ERR, "[moesif] USING MOESIF COMMON FUNCTION payload: ", payload)
--     return payload
--   else
--     if debug then
--       ngx_log(ngx.DEBUG, " [moesif]  ", " USING COMMON FUNCTION successfully compressed body")
--     end
--     payload = string_format(
--       "%s %s HTTP/1.1\r\nHost: %s\r\nConnection: Keep-Alive\r\nX-Moesif-Pid:" .. tostring(ngx.worker.pid()) .. "\r\nX-Moesif-Timer-Start:" .. tostring(timer_start) .. "\r\nX-Moesif-Timer-Delay:" .. tostring(timer_delay_in_seconds) .. "\r\nX-Moesif-Application-Id: %s\r\nUser-Agent: %s\r\nContent-Encoding: %s\r\nContent-Type: application/json\r\nContent-Length: %s\r\n\r\n%s",
--       "POST", parsed_url.path, parsed_url.host, application_id, user_agent_string, "deflate", #compressed_body, compressed_body)
--     return payload
--   end  
-- end


function _M.generate_post_payload(config, parsed_url, message, application_id, user_agent_string, debug, timer_start, timer_delay_in_seconds)

    local body = cjson.encode(message)

    return body
  end

return _M
