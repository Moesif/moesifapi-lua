local _M = {}

local cjson = require "cjson"
local zlib = require "zlib"

-- local function loadModules()
--   local cjson = require "cjson"
--   local zlib = require "zlib"
--   return cjson, zlib
-- end

-- local cjson, zlib = loadModules()

local function compress_data(input_string)
  local compressor = zlib.deflate()
  local compressed_data, eof, bytes_in, bytes_out = compressor(input_string, "finish")
  return compressed_data
end


function _M.generate_post_payload(moesif_ctx, conf, message, debug)

  local body = cjson.encode(message)
  local payload = nil
  local isCompressed = conf.enable_compression

  if conf.enable_compression then 
    local ok, compressed_body = pcall(compress_data, body)
    if not ok then
      if debug then
        moesif_ctx.log(moesif_ctx.DEBUG, "[moesif] failed to compress body: ")
      end
      payload = body
      isCompressed = false 
    else
      if debug then
        moesif_ctx.log(moesif_ctx.DEBUG, " [moesif] successfully compressed body")
      end
      payload = compressed_body
    end
  else
    moesif_ctx.log(moesif_ctx.DEBUG, "[moesif] NO NEED TO compress body: ")
    payload = body
  end
  
  return payload, isCompressed
end

return _M
