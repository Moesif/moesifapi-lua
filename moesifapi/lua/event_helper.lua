local _M = {}

local helpers = require "moesifapi.lua.helpers"
local client_ip = require "moesifapi.lua.client_ip"


local function prepare_reqeust(moesif_ctx, config, request_headers, request_body_entity, req_body_transfer_encoding, api_version)
    local req_start_time = moesif_ctx.req.start_time
    return  {
        uri = helpers.prepare_request_uri(moesif_ctx, config),
        headers = request_headers,
        body = request_body_entity,
        verb = moesif_ctx.req.get_method(),
        ip_address = client_ip.get_client_ip(moesif_ctx, request_headers),
        api_version = api_version,
        time = os.date("!%Y-%m-%dT%H:%M:%S.", req_start_time()) .. string.format("%d",(req_start_time()- string.format("%d", req_start_time()))*1000),
        transfer_encoding = req_body_transfer_encoding,
      }
end

local function prepare_response(moesif_ctx, response_headers, response_body_entity, rsp_body_transfer_encoding)
    local moesif_ctx_now = moesif_ctx.now
    return {
        time = os.date("!%Y-%m-%dT%H:%M:%S.", moesif_ctx_now()) .. string.format("%d",(moesif_ctx_now()- string.format("%d",moesif_ctx_now()))*1000),
        status = moesif_ctx.status,
        ip_address = nil,
        headers = response_headers,
        body = response_body_entity,
        transfer_encoding = rsp_body_transfer_encoding,
      }
end

function _M.prepare_event(moesif_ctx, config, request_headers, request_body_entity, req_body_transfer_encoding, api_version, 
                            response_headers, response_body_entity, rsp_body_transfer_encoding,
                            session_token_entity, user_id_entity, company_id_entity, blocked_by_entity)
    return {
        request = prepare_reqeust(moesif_ctx, config, request_headers, request_body_entity, req_body_transfer_encoding, api_version),
        response = prepare_response(moesif_ctx, response_headers, response_body_entity, rsp_body_transfer_encoding),
        session_token = session_token_entity,
        user_id = user_id_entity,
        company_id = company_id_entity,
        direction = "Incoming",
        blocked_by = blocked_by_entity
      }
end


return _M