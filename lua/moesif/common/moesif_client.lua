local _M = {}

local socket = require "socket"
local http_conn = require "moesif.common.http_connection"
local client_ip = require "moesif.common.client_ip"
local app_config = require "moesif.common.app_config"
local moesif_gov = require "moesif.common.moesif_gov"
local helpers = require "moesif.common.helpers"
local moesif_ctx = nil

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

function _M.get_moesif_client(ctx)
    moesif_ctx = ctx
    ctx.log(ctx.DEBUG, "Inside get_moesif_client " .. tostring(ctx))
    return moesif_ctx
end

function _M.moesif_log(msg)
    moesif_ctx.log(moesif_ctx.DEBUG, msg .." for pid - ".. moesif_ctx.worker.pid())
end

local function get_http_client(conf)

    -- moesif_ctx.log(moesif_ctx.DEBUG, "Inside get_http_connection " .. tostring(moesif_ctx) .. " http_conn - ".. dump(http_conn))

    local create_client_time = socket.gettime()*1000
    local httpc = http_conn.get_client(conf)
    local end_client_time = socket.gettime()*1000

    if conf.debug then
        moesif_ctx.log(moesif_ctx.DEBUG, "[moesif] Create new client took time - ".. tostring(end_client_time - create_client_time))
    end

    return httpc
end

function _M.get_http_connection(conf)
    return get_http_client(conf)
end

function _M.get_client_ip(headers)
    return client_ip.get_client_ip(moesif_ctx, headers)
end

function _M.get_config_internal(config, debug)
    local httpc = get_http_client(config)
    return app_config.get_config_internal(moesif_ctx, httpc, config, debug)
end

function _M.set_default_config_value(conf)
    return helpers.set_default_config_value(moesif_ctx, conf)
end

function _M.govern_request(conf, start_access_phase_time, verb, headers)
    -- moesif_gov.govern_request(moesif_ctx, conf, start_access_phase_time, verb, headers)
    -- Check if need to block incoming request based on user-specified governance rules
    local block_req = moesif_gov.govern_request(moesif_ctx, conf, start_access_phase_time, verb, headers)
    if block_req == nil then 
    if conf.debug then
        moesif_ctx.log(moesif_ctx.DEBUG, '[moesif] No need to block incoming request.')
    end
    local end_access_phase_time = socket.gettime()*1000
    moesif_ctx.log(moesif_ctx.DEBUG, "[moesif] access phase took time for non-blocking request - ".. tostring(end_access_phase_time - start_access_phase_time).." for pid - ".. ngx.worker.pid())
    end
end


return _M