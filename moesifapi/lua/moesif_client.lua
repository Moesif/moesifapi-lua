local _M = {}

local socket = require "socket"
local http_conn = require "moesifapi.lua.http_connection"
local app_config = require "moesifapi.lua.app_config"
local moesif_gov = require "moesifapi.lua.moesif_gov"
local helpers = require "moesifapi.lua.helpers"
local prepare_payload = require "moesifapi.lua.prepare_payload"
local body_helper = require "moesifapi.lua.serializaiton_helper"
local event_helper = require "moesifapi.lua.event_helper"
local regex_config_helper = require "moesifapi.lua.regex_config_helpers"
local moesif_ctx = nil

function _M.get_moesif_client(ctx)
    moesif_ctx = ctx
    return moesif_ctx
end

local function get_http_client(conf)

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

function _M.get_config_internal(config, debug)
    local httpc = get_http_client(config)
    return app_config.get_config_internal(moesif_ctx, httpc, config, debug)
end

function _M.govern_request(conf, start_access_phase_time, verb, headers)
    -- Check if need to block incoming request based on user-specified governance rules
    local block_req = moesif_gov.govern_request(moesif_ctx, conf, start_access_phase_time, verb, headers)
    if block_req == nil then 
        if conf.debug then
            moesif_ctx.log(moesif_ctx.DEBUG, '[moesif] No need to block incoming request.')
        end
        local end_access_phase_time = socket.gettime()*1000
        if conf.debug then
            moesif_ctx.log(moesif_ctx.DEBUG, "[moesif] access phase took time for non-blocking request - ".. tostring(end_access_phase_time - start_access_phase_time).." for pid - ".. moesif_ctx.worker.pid())
        end
    end
end

function _M.generate_post_payload(conf, message, debug)
    return prepare_payload.generate_post_payload(moesif_ctx, conf, message, debug)
end


function _M.parse_body(headers, body, mask_fields, config)
    return body_helper.parse_body(moesif_ctx, headers, body, mask_fields, config)
end

function _M.get_identity_from_auth_header(conf, request_headers)
    return helpers.get_identity_from_auth_header(conf, request_headers)
end

function _M.prepare_event(config, request_headers, request_body_entity, req_body_transfer_encoding, api_version,
    response_headers, response_body_entity, rsp_body_transfer_encoding,
    session_token_entity, user_id_entity, company_id_entity, blocked_by_entity)
    
    return event_helper.prepare_event(moesif_ctx, config, request_headers, request_body_entity, req_body_transfer_encoding, api_version,
                                        response_headers, response_body_entity, rsp_body_transfer_encoding,
                                        session_token_entity, user_id_entity, company_id_entity, blocked_by_entity)
end

function _M.fetch_sample_rate_block_request_on_regex_match(gr_regex_configs, request_config_mapping)
    return regex_config_helper.fetch_sample_rate_block_request_on_regex_match(gr_regex_configs, request_config_mapping)
end 

return _M