local _M = {}
local url = require "socket.url"
local HTTPS = "https"
local cjson = require "cjson"
local base64 = require "moesifapi.lua.base64"


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

-- Prepare request URI
-- @param `moesif_ctx`  Moesif context object
-- @param `conf`     Configuration table, holds http endpoint details
-- @return `url` Request URI
function _M.prepare_request_uri(moesif_ctx, conf)

  local request_uri = moesif_ctx.var.request_uri

  moesif_ctx.log(moesif_ctx.DEBUG, "config in prepare_request_uri - ", dump(conf))

  -- TODO: Add pcall?
  if next(cjson.decode(conf:get("request_query_masks"))) ~= nil and request_uri ~= nil then
    for _, value in ipairs(conf.request_query_masks) do
      request_uri = request_uri:gsub(value.."=[^&]*([^&])", value.."=*****", 1)
    end
  end
  if request_uri == nil then
    request_uri = "/"
  end
  return moesif_ctx.var.scheme .. "://" .. moesif_ctx.var.host .. ":" .. moesif_ctx.var.server_port .. request_uri
end

-- function to parse user id from authorization/user-defined headers
function _M.parse_authorization_header(token, user_id, company_id)
  local user_id_entity = nil
  local company_id_entity = nil
  
  -- Decode the payload
  local base64_decode_ok, payload = pcall(base64.decode, token)
  if base64_decode_ok then
    -- Convert the payload into table
    local json_decode_ok, decoded_payload = pcall(cjson.decode, payload)
    if json_decode_ok then
      -- Fetch the user_id
      if type(decoded_payload) == "table" and next(decoded_payload) ~= nil then 
         -- Convert keys to lowercase
         for k, v in pairs(decoded_payload) do
          decoded_payload[string.lower(k)] = v
        end
        -- Fetch user from the token
        if decoded_payload[user_id] ~= nil then
          user_id_entity = tostring(decoded_payload[user_id])
        end
        -- Fetch company from the token
        if decoded_payload[company_id] ~= nil then
          company_id_entity = tostring(decoded_payload[company_id])
        end
        return user_id_entity, company_id_entity
      end
    end
  end
  return user_id_entity, company_id_entity
end

local function isempty(s)
    return s == nil or s == ''
end  

function _M.set_default_config_value(moesif_ctx, config)
    -- Set Default values.
if isempty(config:get("disable_transaction_id")) then
    config:set("disable_transaction_id", false)
  end
  
  if isempty(config:get("api_endpoint")) then
    config:set("api_endpoint", "https://api.moesif.net")
  end
  
  if isempty(config:get("timeout")) then
    config:set("timeout", 1000)
  end
  
  if isempty(config:get("connect_timeout")) then
    config:set("connect_timeout", 1000)
  end
  
  if isempty(config:get("send_timeout")) then
    config:set("send_timeout", 2000)
  end
  
  if isempty(config:get("keepalive")) then
    config:set("keepalive", 5000)
  end
  
  if isempty(config:get("disable_capture_request_body")) then
    config:set("disable_capture_request_body", false)
  end
  
  if isempty(config:get("disable_capture_response_body")) then
    config:set("disable_capture_response_body", false)
  end
  
  if isempty(config:get("request_masks")) then
    config:set("request_masks", "")
  end
  
  if isempty(config:get("request_body_masks")) then
    config:set("request_body_masks", "")
  end
  
  if isempty(config:get("request_header_masks")) then
    config:set("request_header_masks", "")
  end
  
  if isempty(config:get("response_masks")) then
    config:set("response_masks", "")
  end
  
  if isempty(config:get("response_body_masks")) then
    config:set("response_body_masks", "")
  end
  
  if isempty(config:get("response_header_masks")) then
    config:set("response_header_masks", "")
  end
  
  if isempty(config:get("batch_size")) then
    config:set("batch_size", 200)
  end
  
  if isempty(config:get("debug")) then
    config:set("debug", false)
  end
  
  if isempty(config:get("batch_max_time")) then
    config:set("batch_max_time", 2)
  elseif config:get("batch_max_time") > 30 then 
    moesif_ctx.log(moesif_ctx.ERR, "[moesif] Resetting Batch max time config value (" .. tostring(config:get("batch_max_time")) .. ") to max allowed (30 seconds)");
    config:set("batch_max_time", 30)
  end
  
  if isempty(config:get("max_callback_time_spent")) then
    config:set("max_callback_time_spent", 2000)
  end
  
  if isempty(config:get("disable_gzip_payload_decompression")) then
    config:set("disable_gzip_payload_decompression", false)
  end
  
  if isempty(config:get("queue_scheduled_time")) then
    config:set("queue_scheduled_time", os.time{year=1970, month=1, day=1, hour=0})
  end
  
  if isempty(config:get("max_body_size_limit")) then
    config:set("max_body_size_limit", 100000)
  end
  
  if isempty(config:get("authorization_header_name")) then
    config:set("authorization_header_name", "authorization")
  end
  
  if isempty(config:get("authorization_user_id_field")) then
    config:set("authorization_user_id_field", "sub")
  end

  if isempty(config:get("enable_compression")) then
    config:set("enable_compression", false)
  end
  
  -- TODO: In NGINX's Lua module, shared dictionaries (ngx.shared.my_conf) are designed to hold string-based values or other simple types like numbers, booleans, etc. 
  -- They are not meant to store Lua tables directly, including empty tables, in the same way you would work with Lua's native data structures.
  -- TODO: Figure out - request_query_masks = {default = {}, type = "array", elements = typedefs.header_name}
  if isempty(config:get("request_query_masks")) then
    moesif_ctx.log(moesif_ctx.DEBUG, "config set to default in helpers - ")  
    config:set("request_query_masks", "{}")
  else
    moesif_ctx.log(moesif_ctx.DEBUG, "config not set to default in helpers - ")  
  end

  for _, key in ipairs({"application_id", "debug", "request_query_masks"}) do
    local value = config:get(key)
    ngx.log(ngx.ERR, "Key: ", key, ", Value: ", dump(value) or "nil")
end

  moesif_ctx.log(moesif_ctx.DEBUG, "config return from helpers - ", dump(config))

  return config
end

return _M
