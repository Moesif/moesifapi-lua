local _M = {}

local cjson = require "cjson"
local cjson_safe = require "cjson.safe"
local base64 = require "moesifapi.lua.base64"
local zzlib = require "moesifapi.lua.zzlib"

-- TODO: Compare with the one in the kong
-- Mask Body
local function mask_body(body, masks)
  if masks == nil then return body end
  if body == nil then return body end
  for mask_key, mask_value in pairs(masks) do
    mask_value = mask_value:gsub("%s+", "")
    if body[mask_value] ~= nil then body[mask_value] = nil end
    for body_key, body_value in next, body do
        if type(body_value)=="table" then mask_body(body_value, masks) end
    end
  end
  return body
end

local function base64_encode_body(body)
  return base64.encode(body), 'base64'
end

local function is_valid_json(body)
    return type(body) == "string" 
        and string.sub(body, 1, 1) == "{" or string.sub(body, 1, 1) == "["
end

local function process_data(body, mask_fields)
  local body_entity = nil
  local body_transfer_encoding = nil
  local is_deserialised, deserialised_body = pcall(cjson_safe.decode, body)
  if not is_deserialised  then
      body_entity, body_transfer_encoding = base64_encode_body(body)
  else
      if next(mask_fields) == nil then
          body_entity, body_transfer_encoding = deserialised_body, 'json' 
      else
          local ok, mask_result = pcall(mask_body, deserialised_body, mask_fields)
          if not ok then
            body_entity, body_transfer_encoding = deserialised_body, 'json' 
          else
            body_entity, body_transfer_encoding = mask_result, 'json' 
          end
      end
  end
  return body_entity, body_transfer_encoding
end

local function decompress_body(moesif_ctx, body, masks, config)
  local body_entity = nil
  local body_transfer_encoding = nil

  local ok, decompressed_body = pcall(zzlib.gunzip, body)
  if not ok then
    if config:get("debug") then
        moesif_ctx.log(moesif_ctx.DEBUG, "[moesif] failed to decompress body: ", decompressed_body)
    end
    body_entity, body_transfer_encoding = base64_encode_body(body)
  else
    if config:get("debug") then
        moesif_ctx.log(moesif_ctx.DEBUG, " [moesif]  ", "successfully decompressed body: ")
    end
    if is_valid_json(decompressed_body) then 
        body_entity, body_transfer_encoding = process_data(decompressed_body, masks)
    else 
        body_entity, body_transfer_encoding = base64_encode_body(decompressed_body)
    end
  end
  return body_entity, body_transfer_encoding
end

function _M.mask_headers(headers, mask_fields)
  local mask_headers = nil

  for k,v in pairs(mask_fields) do
    mask_fields[k] = v:lower()
  end

  local ok, mask_result = pcall(mask_body, headers, mask_fields)
  if not ok then
    mask_headers = headers
  else
    mask_headers = mask_result
  end
  return mask_headers
end

function _M.mask_body_fields(body_masks_config, deprecated_body_masks_config)
  if next(body_masks_config) == nil then
    return deprecated_body_masks_config
  else
    return body_masks_config
  end
end

function _M.parse_body(moesif_ctx, headers, body, mask_fields, config)
  local body_entity = nil
  local body_transfer_encoding = nil

  if headers["content-type"] ~= nil and is_valid_json(body) then -- and string.find(headers["content-type"], "json")
    body_entity, body_transfer_encoding = process_data(body, mask_fields)
  elseif headers["content-encoding"] ~= nil and type(body) == "string" and string.find(headers["content-encoding"], "gzip") then
    if not config:get("disable_gzip_payload_decompression") then 
      body_entity, body_transfer_encoding = decompress_body(moesif_ctx, body, mask_fields, config)
    else
      body_entity, body_transfer_encoding = base64_encode_body(body)
    end
  else
    body_entity, body_transfer_encoding = base64_encode_body(body)
  end
  return body_entity, body_transfer_encoding
end

return _M