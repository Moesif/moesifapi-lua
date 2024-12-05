local _M = {}

local cjson = require "cjson"
local base64 = require "moesifapi.lua.base64"

-- Split the string
function _M.split(str, character)
  local result = {}

  local index = 1
  for s in string.gmatch(str, "[^"..character.."]+") do
    result[index] = s
    index = index + 1
  end

  return result
end

-- Prepare request URI
-- @param `moesif_ctx`  Moesif context object
-- @param `conf`     Configuration table, holds http endpoint details
-- @return `url` Request URI
function _M.prepare_request_uri(moesif_ctx, conf)

  local request_uri = moesif_ctx.var.request_uri

  local request_query_masks = _M.split(conf:get("request_query_masks"), ",")
  if next(request_query_masks) ~= nil and request_uri ~= nil then
    for _, value in ipairs(request_query_masks) do
      request_uri = request_uri:gsub(value.."=[^&]*([^&])", value.."=*****", 1)
    end
  end
  if request_uri == nil then
    request_uri = "/"
  end
  return moesif_ctx.var.scheme .. "://" .. moesif_ctx.var.host .. ":" .. moesif_ctx.var.server_port .. request_uri
end

-- function to parse user id from authorization/user-defined headers
local function parse_authorization_header(token, user_id, company_id)
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

-- Split the string by delimiter
-- @param `str`        String
-- @param `character`  Delimiter
local function split(str, character)
  local result = {}

  local index = 1
  for s in string.gmatch(str, "[^"..character.."]+") do
    result[index] = s
    index = index + 1
  end

  return result
end

-- Function to split token by dot(.)
function split_token(token)
  local split_token = {}
  for line in token:gsub("%f[.]%.%f[^.]", "\0"):gmatch"%Z+" do 
      table.insert(split_token, line)
  end
  return split_token
end

function _M.get_identity_from_auth_header(conf, request_headers)

  local user_id_entity = nil
  local company_id_entity = nil

  -- Split authorization header name by comma
  local auth_header_names = split(string.lower(conf:get("authorization_header_name")), ",") 
  local token = nil

  -- Fetch the token and field from the config
  for _, name in pairs(auth_header_names) do
      local auth_name = name:gsub("%s+", "")
      if request_headers[auth_name] ~= nil then 
        if type(request_headers[auth_name]) == "table" and (request_headers[auth_name][0] ~= nil or request_headers[auth_name][1] ~= nil) then 
          token = request_headers[auth_name][0] or request_headers[auth_name][1]
        else
          token = request_headers[auth_name]
        end
        break
      end
  end
  local user_id_field = conf:get("authorization_user_id_field")
  local company_id_field = conf:get("authorization_company_id_field")

  if token ~= nil then 
      -- Check if token is of type Bearer
      if string.match(token, "Bearer") then
          -- Fetch the bearer token
          token = token:gsub("Bearer", "")
          
          -- Split the bearer token by dot(.)
          local split_token = split_token(token)
          
          -- Check if payload is not nil
          if split_token[2] ~= nil then 
              -- Parse and set user Id
              user_id_entity, company_id_entity = parse_authorization_header(split_token[2], user_id_field, company_id_field)
          else
              user_id_entity = nil  
          end 
      -- Check if token is of type Basic
      elseif string.match(token, "Basic") then
          -- Fetch the basic token
          token = token:gsub("Basic", "")
          -- Decode the token
          local decoded_token = base64.decode(token)
          -- Fetch the username and password
          local username, _ = decoded_token:match("(.*):(.*)")
          
          -- Set the user_id
          if username ~= nil then
              user_id_entity = username 
          else
              user_id_entity = nil 
          end 
      -- Check if token is of user-defined custom type
      else
          -- Split the bearer token by dot(.)
          local split_token = split_token(token)
                          
          -- Check if payload is not nil
          if split_token[2] ~= nil then 
              -- Parse and set user Id
              user_id_entity, company_id_entity = parse_authorization_header(split_token[2], user_id_field, company_id_field)
          else
              -- Parse and set the user_id
              user_id_entity, company_id_entity = parse_authorization_header(token, user_id_field, company_id_field)
          end 
      end
  else
      user_id_entity = nil
  end
  return user_id_entity, company_id_entity
end

return _M
