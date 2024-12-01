
local _M = {}

local http_conn = require "moesifapi.lua.http_connection"
local gr_helpers = require "moesifapi.lua.governance_helpers"
local cjson = require "cjson"
entity_rules_hashes = {}

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

          -- Check if the governance rule is updated
          local response_rules_etag = config_response.headers["x-moesif-rules-tag"]
          if response_rules_etag ~= nil then
            config["rulesETag"] = response_rules_etag
          end

          ctx.log(ctx.DEBUG, "[moesif] config.application_id - ", dump(config.application_id))

          -- Hash key of the config application Id
         local hash_key = string.sub(config.application_id, -10)

         ctx.log(ctx.DEBUG, "[moesif] hash_key - ", dump(hash_key))

          local entity_rules = {}
          -- Create empty table for user/company rules
          entity_rules[hash_key] = {}

          -- Get governance rules
        if (governance_rules_etags[hash_key] == nil or (config["rulesETag"] ~= governance_rules_etags[hash_key])) then
            gr_helpers.get_governance_rules(httpc, hash_key, config)
          end
  
          if (response_body["user_rules"] ~= nil) then
            entity_rules[hash_key]["user_rules"] = response_body["user_rules"]
          end
  
          if (response_body["company_rules"] ~= nil) then
              entity_rules[hash_key]["company_rules"] = response_body["company_rules"]
          end

          -- generate entity merge tag values mapping
          entity_rules_hashes[hash_key] = generate_entity_rule_values_mapping(hash_key, entity_rules)
  
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