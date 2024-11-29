
local _M = {}

local http_conn = require "moesif.common.http_connection"
local cjson = require "cjson"

function _M.get_config_internal(ctx, httpc, config, debug)

    
    -- Send the request to fetch config
    local config_response, config_response_error = http_conn.get_request(httpc, config, "/v1/config")
  
    if config_response_error == nil then 
      if config_response ~= nil then
  
        local raw_config_response = config_response.body
  
        ctx.log(ctx.DEBUG, "[moesif] THE RAW CONFIG RESPONSE IS - ".. raw_config_response)
  
        if raw_config_response ~= nil then
          local response_body = cjson.decode(raw_config_response)
          local config_tag = config_response.headers["x-moesif-config-etag"]
  
          if config_tag ~= nil then
            config["ETag"] = config_tag
          end
  
          if (config["sample_rate"] ~= nil) and (response_body ~= nil) then
  
            if (response_body["user_sample_rate"] ~= nil) then
              config["user_sample_rate"] = response_body["user_sample_rate"]
            end
  
            if (response_body["company_sample_rate"] ~= nil) then
              config["company_sample_rate"] = response_body["company_sample_rate"]
            end
  
            if (response_body["regex_config"] ~= nil) then
              config["regex_config"] = response_body["regex_config"]
            end
  
            if (response_body["sample_rate"] ~= nil) then 
              config["sample_rate"] = response_body["sample_rate"]
            end
          end
          config.is_config_fetched = true
          -- TODO: config.config_last_fetch_time to current time 
        else
          if debug then
            ctx.log(ctx.DEBUG, "[moesif] raw config response is nil so could not decode it, the config response is - " .. tostring(config_response))
          end
        end
      else
        ctx.log(ctx.DEBUG, "[moesif] application config is nil ")
      end
    else 
        ctx.log(ctx.DEBUG,"[moesif] error while reading response after fetching app config - ", config_response_error)
    end
    return config_response
  end

  return _M