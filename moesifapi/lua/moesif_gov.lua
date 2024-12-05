local _M = {}

local helper = require "moesifapi.lua.helpers"
local regex_config_helper = require "moesifapi.lua.regex_config_helpers"
local client_ip = require "moesifapi.lua.client_ip"
local socket = require "socket"
local cjson = require "cjson"


-- Replace body value in the response body for the short-circuited request
-- @param `body_table`    Response Body
-- @param `rule_values`   Governance Rule values
local function transform_values(body_table, rule_values)
    if type(body_table) == "string" then
        return body_table:gsub("{{%d+}}", rule_values)
    elseif type(body_table) == "table" and next(body_table) ~= nil then 
        local updated_body_table = {}
        for k,v in pairs(body_table) do updated_body_table[k]=v end

        for key, headerValue in pairs(updated_body_table) do 
            if type(headerValue) == "string" then
                updated_body_table[key] = headerValue:gsub("{{%d+}}", rule_values)
            elseif type(headerValue) == "table" and next(headerValue) ~= nil then 
                local updatedBody = transform_values(headerValue, rule_values)
                updated_body_table[key] = updatedBody
            end
        end
        return updated_body_table
    end
end

-- Fill in merge tag values in response header and body
-- @param `gr_body`         Response Body
-- @param `gr_headers`      Response header
-- @param `matched_governance_rules`    All matched rules object
-- @param `entity_merge_tag_values`     Rule id to entity merge tag mapping
local function get_updated_response_body_and_headers(moesif_ctx, gr_body, block_by, all_gr_headers, matched_governance_rules, entity_merge_tag_values, debug)
    -- initial governance rule headers
    local update_accumulate_gr_headers = {}

    -- initial governance rule body
    local update_gr_body = {}

    for _, rule in pairs(matched_governance_rules) do
        if rule["_id"] ~= nil then
            local rule_id = rule["_id"]

            -- governance rule variables
            local rule_variables = {}
            if rule["variables"] then
                rule_variables = rule["variables"]
            end

            -- merge tag value from /config
            local merge_tag_values = {}
            if entity_merge_tag_values[rule_id] ~= nil then
                merge_tag_values = entity_merge_tag_values[rule_id]
            end

            -- build rule value mapping with UNKNOWN values
            local updated_rule_values = {}
            if next(rule_variables) ~= nil then
                updated_rule_values = generate_update_rule_values(moesif_ctx, merge_tag_values, rule_variables, debug)
            end

            -- update body with the rule blocked_by
            if rule_id == block_by then
                -- Replace body
                update_gr_body = transform_values(gr_body, updated_rule_values)
            end

            -- accumulate all headers with matched rule order
            if all_gr_headers[rule_id] then
                local gr_headers = all_gr_headers[rule_id]
                if gr_headers then
                    local updated_gr_headers = transform_values(gr_headers, updated_rule_values)
                    if updated_gr_headers then
                        for k, v in pairs(updated_gr_headers) do
                            if update_accumulate_gr_headers[k] == nil then
                                update_accumulate_gr_headers[k] = v
                            end
                        end
                    end
                end
            end
        end
    end
    return update_gr_body, update_accumulate_gr_headers
end

-- TODO: If need to be local 
function generate_update_rule_values(moesif_ctx, merge_tag_values, rule_variables, debug)
    local updated_rule_values = {}
    local ok, rule_variables_map = pcall(create_rule_variables_map, rule_variables)

    if ok then
        for k, v in pairs(rule_variables_map) do
            if merge_tag_values[k] == nil then
                updated_rule_values["{{"..k.."}}"] = "UNKNOWN"
            else
                updated_rule_values["{{"..k.."}}"] = merge_tag_values[k]
            end
        end
    else
        if debug then
            moesif_ctx.log(moesif_ctx.DEBUG, "[moesif] Error when pursing governance rule variables | "..rule_variables_map)
        end
    end
    return updated_rule_values
end

-- convert variables map from governance rule, e.g. from {"name": "0","path": "user_id"} to {"0":"user_id"}
-- @param rule_variables
function create_rule_variables_map(rule_variables)
    local rule_variables_map = {}
    for _, name_and_path in pairs(rule_variables) do
        rule_variables_map[name_and_path["name"]] = name_and_path["path"]
    end
    return rule_variables_map
end

-- Fetch response status, headers, and body from the governance rule
-- @param `governance_rule`          Governance Rule
-- @return `status, headers, body`   Response status, headers, body
function fetch_governance_rule_response_details(governance_rule)
    -- Response status
    local status = governance_rule["response"]["status"]
    -- Response headers
    local headers = governance_rule["response"]["headers"]
    -- Response body
    local body
    if governance_rule["response"]["body"] ~= nil then
        body = governance_rule["response"]["body"]
    end
   return status, headers, body
end

function check_if_apply_rule_by_apply_to(moesif_ctx, hash_key, entity_rule_type, entity_id, rule_id, rule, debug)
    local applied_to = AppliedTo.MATCHING
    if rule["applied_to"] then
        applied_to = rule["applied_to"]
    end

    local is_in_cohort = is_entity_in_cohort(hash_key, entity_rule_type, entity_id, rule_id)

    if (is_in_cohort and applied_to == AppliedTo.MATCHING) or (not is_in_cohort and applied_to == AppliedTo.NOT_MATCHING) then
        return true
    else
        if debug then
            moesif_ctx.log(moesif_ctx.DEBUG, "[moesif] Skipped blocking request as entity governance rule"  ..rule_id.. " because entity " ..entity_id.. " is in cohort["..tostring(is_in_cohort).."] and applied_to is set as "..applied_to)
        end
        return false
    end
end

-- Function to check if an entity belongs to a cohort which has any gov rules enabled
function is_entity_in_cohort(hash_key, entity_rule_type, entity_id, matched_rule_id)
    if type(entity_rules_hashes[hash_key]) == "table" and next(entity_rules_hashes[hash_key]) ~= nil
        and type(entity_rules_hashes[hash_key][entity_rule_type]) == "table" and next(entity_rules_hashes[hash_key][entity_rule_type]) then
        return type(entity_rules_hashes[hash_key][entity_rule_type][entity_id]) == "table" and 
                    entity_rules_hashes[hash_key][entity_rule_type][entity_id] ~= nil and 
                    next(entity_rules_hashes[hash_key][entity_rule_type][entity_id]) ~= nil and 
                    type(entity_rules_hashes[hash_key][entity_rule_type][entity_id][matched_rule_id]) == "table" and 
                    entity_rules_hashes[hash_key][entity_rule_type][entity_id][matched_rule_id] ~= nil 
    end
    return false
end

-- Transform flatten entity mapping to map(hash_key -> {entity rule type -> {entity id -> {rule_id -> rule}}})
function generate_entity_rule_values_mapping(hash_key, entity_rules)
    local entity_rule_values = {}
    for entity_rule_type, entities in pairs(entity_rules[hash_key]) do
        if entity_rule_values[entity_rule_type] == nil then
            entity_rule_values[entity_rule_type] = {}
        end
        for entity_id, rule_values in pairs(entities) do
            if rule_values ~= nil then
                -- remap rule and values
                local remapped_rule_values = {}
                for _, rule in pairs(rule_values) do
                    local rule_id = rule["rules"]
                    if rule_id ~= nil then
                        -- If the gov rule response body has any merged tags, include the values else empty table
                        -- so that we ensure all the gov rules are added to the map
                        if rule["values"] ~= nil then 
                            remapped_rule_values[rule_id] = rule["values"]
                        else
                            remapped_rule_values[rule_id] = {}
                        end
                    end
                end
                entity_rule_values[entity_rule_type][entity_id] = remapped_rule_values
            end
        end
    end
    return entity_rule_values
end

function is_blocked_by(moesif_ctx, governance_rule)
    if governance_rule["block"] ~= nil then
        return governance_rule["block"]
    else
        moesif_ctx.log(moesif_ctx.DEBUG, "[moesif] Error when parsing block fields in governance rule: " ..governance_rule)
        return false
    end
end

-- Fetch response status and body from the governance rule
-- @param `governance_rule`          Governance Rule
-- @return `status, headers, body`   Response status, body
function fetch_governance_rule_response_status_and_body(governance_rule)
    -- Response status
    local status = governance_rule["response"]["status"]
    -- Response body
    local body = governance_rule["response"]["body"]
    return status, body
end

-- Fetch response headers from the governance rule
-- @param `governance_rule`          Governance Rule
-- @return `status, headers, body`   Response status, headers, body
function fetch_governance_rule_response_headers(governance_rule)
    -- Response headers
    local headers = governance_rule["response"]["headers"]
    return headers
end

function get_all_blocked_response_headers(moesif_ctx, matched_rules)
    local all_rule_id_to_gr_headers = {}
    for _, rule in pairs(matched_rules) do
        local rule_id
        if rule["_id"] then
            rule_id = rule["_id"]
            local ok, gr_headers = pcall(fetch_governance_rule_response_headers, rule)
            if not ok then
                moesif_ctx.log(moesif_ctx.DEBUG, "[moesif] Error when parsing headers fields in governance rule["..rule_id.."] | "..gr_headers)
            else
                all_rule_id_to_gr_headers[rule_id] = gr_headers
            end
        else
            moesif_ctx.log(moesif_ctx.DEBUG, "[moesif] Error when parsing _id fields in governance rule: " ..rule)
        end
    end

    return all_rule_id_to_gr_headers
end

function generate_blocked_response_status_code_body_and_block_by(moesif_ctx, matched_rules)
    for _, rule in pairs(matched_rules) do
        if is_blocked_by(moesif_ctx, rule) then
            if rule["_id"] ~= nil then
                local block_by = rule["_id"]
                local ok, gr_status, gr_body = pcall(fetch_governance_rule_response_status_and_body, rule)
                if not ok then
                    moesif_ctx.log(moesif_ctx.DEBUG, "[moesif] Error when parsing status or body fields in governance rule["..block_by.."] | "..gr_status)
                else
                    return gr_status, gr_body, block_by
                end
            else
                moesif_ctx.log(moesif_ctx.DEBUG, "[moesif] Error when parsing _id fields in governance rule | "..rule)
            end
        end
    end
    return nil, nil, nil
end

function merge_user_and_company_merge_tag_values(hash_key, user_id, company_id)
    local user_and_company_merge_tag_values = {}
    if entity_rules_hashes[hash_key] ~= nil and entity_rules_hashes[hash_key]["user_rules"] ~= nil and entity_rules_hashes[hash_key]["user_rules"][user_id] ~= nil and next(entity_rules_hashes[hash_key]["user_rules"][user_id]) ~= nil then
        user_and_company_merge_tag_values = entity_rules_hashes[hash_key]["user_rules"][user_id]
    end
    if entity_rules_hashes[hash_key] ~= nil and entity_rules_hashes[hash_key]["company_rules"] ~= nil and entity_rules_hashes[hash_key]["company_rules"][company_id] ~= nil and next(entity_rules_hashes[hash_key]["company_rules"][company_id]) ~= nil then
        local company_merge_tag_values = entity_rules_hashes[hash_key]["company_rules"][company_id]
        for rule_id, merge_tag_values in pairs(company_merge_tag_values) do
            user_and_company_merge_tag_values[rule_id] = merge_tag_values
        end
    end
    return user_and_company_merge_tag_values
end

-- Check if need to block request based on the governance rule regex config associated with the request
-- @param `hash_key`                Hash key of the config application Id
-- @param `rule_name`               Type of rules in entity rules config [user_rules, company_rules]
-- @param `rule_id`                 Governance rule id
-- @param `conf`                    Configuration table, holds http endpoint details
-- @param `start_access_phase_time` Access phase start time
function generate_gov_rule_response(moesif_ctx, hash_key, matched_governance_rules, user_id, company_id, start_access_phase_time, debug)

    -- Generate status code and body with higher priority block rule
    local gr_status, gr_body, block_by = generate_blocked_response_status_code_body_and_block_by(moesif_ctx, matched_governance_rules)
    if not block_by then
        return nil
    end

    -- Generate accumulated headers on all rules(include both unblock and block rules)
    local all_gr_headers = get_all_blocked_response_headers(moesif_ctx, matched_governance_rules)

    -- Get all entity rules for both user and company
    local merge_tag_values = merge_user_and_company_merge_tag_values(hash_key, user_id, company_id)

    -- Combine status, body and headers all together to response
    -- gr_body, block_by, all_gr_headers, matched_governance_rules, entity_merge_tag_values, debug
    local rendered_body, rendered_headers = get_updated_response_body_and_headers(moesif_ctx, gr_body, block_by, all_gr_headers, matched_governance_rules, merge_tag_values, debug)

    -- Add blocked_by field to the event to determine the rule by which the event was blocked
    moesif_ctx.ctx.moesif["blocked_by"] = block_by

    local end_access_phase_time = socket.gettime()*1000
    if debug then
        moesif_ctx.log(moesif_ctx.DEBUG, "[moesif] access phase took time for blocking request - ".. tostring(end_access_phase_time - start_access_phase_time).." for pid - ".. moesif_ctx.worker.pid())
    end

    -- TODO: Figure out
    -- return error("should short circuit return here -")
    -- return kong.response.exit(gr_status, rendered_body, rendered_headers)

    -- Set the response status code (e.g., 200, 404, etc.)
    moesif_ctx.status = gr_status

    -- Set the response headers
    for key, value in pairs(rendered_headers) do
        moesif_ctx.header[key] = value
    end

    -- Set the response body (the content to return to the client)
    moesif_ctx.say(cjson.encode(rendered_body))

    -- Terminate the request and send the response
    moesif_ctx.exit(moesif_ctx.status)

end

-- Check if need to block request based on the governance rule of the entity associated with the request, return a list of governance rules, return empty if no rule matches
-- @param `hash_key`                Hash key of the config application Id
-- @param `conf`                    Configuration table, holds http endpoint details
-- @param `rule_name`               User or Company 
-- @param `entity_id`               User or Company Id associated with the reqeust
-- @param `start_access_phase_time` Access phase start time
-- @param `request_config_mapping`  Request config mapping associated with the request
function block_request_based_on_entity_governance_rule(moesif_ctx, hash_key, governance_rules, entity_rule_type, entity_id, request_config_mapping, debug)
    local matched_rules = {}
    if governance_rules  ~= nil and type(governance_rules) == "table" and next(governance_rules) ~= nil then

        for rule_id, rule in pairs(governance_rules) do
            -- Don't block if entity_rule has regex config and doesn't match
            local ok, matched = pcall(regex_config_helper.check_event_should_blocked_by_rule, rule, request_config_mapping)

            if not ok then
                if debug then
                    moesif_ctx.log(moesif_ctx.DEBUG, "[moesif] Skipped blocking request as entity governance rule" ..rule_id.. " fetching issue")
                end
            else
                -- If the regex conditions does not match, skip blocking the request
                if not matched then
                    if debug then
                        moesif_ctx.log(moesif_ctx.DEBUG, "[moesif] Skipped blocking request as entity governance rule" ..rule_id.. " regex conditions does not match")
                    end
                else
                    if check_if_apply_rule_by_apply_to(moesif_ctx, hash_key, entity_rule_type, entity_id, rule_id, rule, debug) then
                        table.insert(matched_rules, rule)
                    end
                end
            end
        end
    else
        if debug then
            moesif_ctx.log(moesif_ctx.DEBUG, "[moesif] Skipped blocking request since no identified governance rules defined for entity Id - "..entity_id)
        end
    end

    return matched_rules
end

function get_rules(moesif_ctx, hash_key, rule_type, is_applied_to_unidentified, debug)
    local governance_rules = {}
    if rule_type == RuleType.USER or rule_type == RuleType.COMPANY then
        if governance_rules_hashes[hash_key] ~= nil and type(governance_rules_hashes[hash_key]) == "table"
        and governance_rules_hashes[hash_key][rule_type] ~= nil and type(governance_rules_hashes[hash_key][rule_type]) == "table"
        and governance_rules_hashes[hash_key][rule_type][is_applied_to_unidentified] ~= nil
        and type(governance_rules_hashes[hash_key][rule_type][is_applied_to_unidentified]) == "table" then
            governance_rules = governance_rules_hashes[hash_key][rule_type][is_applied_to_unidentified]
        else
            if debug then
                moesif_ctx.log(moesif_ctx.DEBUG, "[moesif] No "..rule_type.. " governance rules defined [Hash key: " ..hash_key.. "]")
            end
        end

    elseif rule_type == RuleType.REGEX then
        if regex_governance_rules_hashes[hash_key] ~= nil and type(regex_governance_rules_hashes[hash_key]) == "table" and next(regex_governance_rules_hashes[hash_key]) ~= nil then
            governance_rules = regex_governance_rules_hashes[hash_key]
        else
            if debug then
                moesif_ctx.log(moesif_ctx.DEBUG, "[moesif] No "..rule_type.. " governance rules defined [Hash key: " ..hash_key.. "]")
            end
        end

    else
        if debug then
            moesif_ctx.log(moesif_ctx.DEBUG, "[moesif] rule_type " ..rule_type.. " is not defined, should be in [user, company or regex]")
        end
    end
    return governance_rules
end

function concat_list(combination, added_list)
    for _, item in pairs(added_list) do
        table.insert(combination, item)
    end
end

function _M.govern_request(moesif_ctx, conf, start_access_phase_time, verb, headers)

    -- Hash key of the config application Id
    -- local hash_key = string.sub(conf.application_id, -10)
    local hash_key = string.sub(conf:get("application_id"), -10)
    local user_id_entity = nil
    local company_id_entity = nil
    local request_uri = helper.prepare_request_uri(moesif_ctx, conf)
    local request_verb = verb
    local request_headers = headers
    local request_ip_address = client_ip.get_client_ip(moesif_ctx, request_headers)
    local request_body = moesif_ctx.ctx.moesif.req_body
    local request_config_mapping = regex_config_helper.prepare_config_mapping(regex_config_helper.prepare_request_config_mapping(request_verb, request_uri, request_ip_address, request_headers, request_body), hash_key)

    -- company id
    -- Fetch the company details
    if conf.company_id_header ~= nil and request_headers[conf.company_id_header] ~= nil then
        company_id_entity = tostring(request_headers[conf.company_id_header])
    end

    -- Fetch the user details
    if conf.user_id_header ~= nil and request_headers[conf.user_id_header] ~= nil then
        user_id_entity = tostring(request_headers[conf.user_id_header])
    elseif request_headers["x-consumer-custom-id"] ~= nil then
        user_id_entity = tostring(request_headers["x-consumer-custom-id"])
    elseif request_headers["x-consumer-username"] ~= nil then
        user_id_entity = tostring(request_headers["x-consumer-username"])
    elseif request_headers["x-consumer-id"] ~= nil then
        user_id_entity = tostring(request_headers["x-consumer-id"])
    elseif conf.authorization_header_name ~= nil and (conf.authorization_user_id_field ~= nil or (company_id_entity == nil and conf.authorization_company_id_field ~= "" and conf.authorization_company_id_field ~= nil)) then
        user_id_entity, company_id_entity = helper.get_identity_from_auth_header(conf, request_headers)
    else
        user_id_entity = nil
    end



    -- Set entity in conf to use downstream
    if moesif_ctx.ctx.moesif["user_id_entity"] == nil and user_id_entity ~= nil then 
        moesif_ctx.ctx.moesif["user_id_entity"] = user_id_entity
        if conf.debug then
            moesif_ctx.log(moesif_ctx.DEBUG, "[moesif] User Id from governance info: " .. user_id_entity)
        end
    end
    if moesif_ctx.ctx.moesif["company_id_entity"] == nil and company_id_entity ~= nil then 
        moesif_ctx.ctx.moesif["company_id_entity"] = company_id_entity
        if conf.debug then
            moesif_ctx.log(moesif_ctx.DEBUG, "[moesif] Company Id from governance info: " .. company_id_entity)
        end
    end

    local matched_rules = {}

    local identified_user_gov_rules = get_rules(moesif_ctx, hash_key, RuleType.USER, "identified", conf.debug)
    -- Check if need to block request based on identified user governance rule
    if user_id_entity ~= nil and identified_user_gov_rules ~= nil and type(identified_user_gov_rules) == "table" and next(identified_user_gov_rules) ~= nil then
        local user_identified_matched_rules = block_request_based_on_entity_governance_rule(moesif_ctx, hash_key, identified_user_gov_rules, "user_rules", user_id_entity, request_config_mapping, conf.debug)
        if user_identified_matched_rules == nil or next(user_identified_matched_rules) == nil then
            if conf.debug then
                moesif_ctx.log(moesif_ctx.DEBUG, "[moesif] Skipped blocking request based on the user Id - " .. user_id_entity)
            end
        else
            if conf.debug then
                moesif_ctx.log(moesif_ctx.DEBUG, "Matched user_identified_matched_rules: ")
                for _, rule in pairs(user_identified_matched_rules) do
                    moesif_ctx.log(moesif_ctx.DEBUG, rule["name"])
                end
            end
            concat_list(matched_rules, user_identified_matched_rules)
        end
    end

    local unidentified_user_gov_rules = get_rules(moesif_ctx, hash_key, RuleType.USER, "unidentified", conf.debug)
    -- Check if need to block request based on unidentified user governance rule
    if unidentified_user_gov_rules ~= nil and type(unidentified_user_gov_rules) == "table" and next(unidentified_user_gov_rules) ~= nil then
        if user_id_entity == nil then
            -- Check if the governance rule regex config matches request config mapping and unidentified user governance rules
            local null_user_unidentified_matched_rules = regex_config_helper.fetch_governance_rule_id_on_regex_match(moesif_ctx, unidentified_user_gov_rules, request_config_mapping, conf.debug)
            -- Check if need to block request based on governance rule regex config
            if null_user_unidentified_matched_rules == nil or next(null_user_unidentified_matched_rules) == nil then
                if conf.debug then
                    moesif_ctx.log(moesif_ctx.DEBUG, "[moesif] Skipped blocking request based on the unidentified user governance rules with undefined user")
                end
            else
                if conf.debug then
                    moesif_ctx.log(moesif_ctx.DEBUG, "Matched null_user_unidentified_matched_rules: ")
                    for _, rule in pairs(null_user_unidentified_matched_rules) do
                        moesif_ctx.log(moesif_ctx.DEBUG, rule["name"])
                    end
                end
                concat_list(matched_rules, null_user_unidentified_matched_rules)
            end
        else
            local user_unidentified_matched_rules = block_request_based_on_entity_governance_rule(moesif_ctx, hash_key, unidentified_user_gov_rules, "user_rules", user_id_entity, request_config_mapping, conf.debug)
            if user_unidentified_matched_rules == nil or next(user_unidentified_matched_rules) == nil then
                if conf.debug then
                    moesif_ctx.log(moesif_ctx.DEBUG, "[moesif] Skipped blocking request based on the unidentified user governance rule user_id - " ..user_id_entity)
                end
            else
                if conf.debug then
                    moesif_ctx.log(moesif_ctx.DEBUG, "Matched user_unidentified_matched_rules: ")
                    for _, rule in pairs(user_unidentified_matched_rules) do
                        moesif_ctx.log(moesif_ctx.DEBUG, rule["name"])
                    end
                end
                concat_list(matched_rules, user_unidentified_matched_rules)
            end
        end
    end

    local identified_company_gov_rules = get_rules(moesif_ctx, hash_key, RuleType.COMPANY, "identified", conf.debug)
    -- Check if need to block request based on identified company governance rule
    if company_id_entity ~= nil and identified_company_gov_rules ~= nil and type(identified_company_gov_rules) == "table" and next(identified_company_gov_rules) ~= nil then
        local company_identified_matched_rules = block_request_based_on_entity_governance_rule(moesif_ctx, hash_key, identified_company_gov_rules, "company_rules", company_id_entity, request_config_mapping,  conf.debug)
        if conf.debug then
            if company_identified_matched_rules == nil or next(company_identified_matched_rules) == nil then
                moesif_ctx.log(moesif_ctx.DEBUG, "[moesif] Skipped blocking request based on the company Id - " .. company_id_entity)
            else
                moesif_ctx.log(moesif_ctx.DEBUG, "[moesif] Matched company_identified_matched_rules: ")
                for _, rule in pairs(company_identified_matched_rules) do
                    moesif_ctx.log(moesif_ctx.DEBUG, rule["name"])
                end
                concat_list(matched_rules, company_identified_matched_rules)
            end
        end
    end

    local unidentified_company_gov_rules = get_rules(moesif_ctx, hash_key, RuleType.COMPANY, "unidentified", conf.debug)
    -- Check if need to block request based on unidentified company governance rule
    if unidentified_company_gov_rules ~= nil and type(unidentified_company_gov_rules) == "table" and next(unidentified_company_gov_rules) ~= nil then
        if company_id_entity == nil then
            -- Check if the governance rule regex config matches request config mapping and unidentified company rules
            local null_company_unidentified_matched_rules = regex_config_helper.fetch_governance_rule_id_on_regex_match(moesif_ctx, unidentified_company_gov_rules, request_config_mapping, conf)
            -- Check if need to block request based on governance rule regex config
            if null_company_unidentified_matched_rules == nil or next(null_company_unidentified_matched_rules) == nil then
                if conf.debug then
                    moesif_ctx.log(moesif_ctx.DEBUG, "[moesif] Skipped blocking request based on the unidentified company governance rules with undefined company")
                end
            else
                if conf.debug then
                    moesif_ctx.log(moesif_ctx.DEBUG, "[moesif] Matched null_company_unidentified_matched_rules: ")
                    for _, rule in pairs(null_company_unidentified_matched_rules) do
                        moesif_ctx.log(moesif_ctx.DEBUG, rule["name"])
                    end
                end
                concat_list(matched_rules, null_company_unidentified_matched_rules)
            end
        else
            local company_unidentified_matched_rules = block_request_based_on_entity_governance_rule(moesif_ctx, hash_key, unidentified_company_gov_rules, "company_rules", company_id_entity, request_config_mapping, conf.debug)
            if company_unidentified_matched_rules == nil  or next(company_unidentified_matched_rules) == nil then
                if conf.debug then
                    moesif_ctx.log(moesif_ctx.DEBUG, "[moesif] Skipped blocking request based on the unidentified company governance rules | company_id - " ..company_id_entity)
                end
            else
                if conf.debug then
                    moesif_ctx.log(moesif_ctx.DEBUG, "[moesif] Matched company_unidentified_matched_rules: ")
                    for _, rule in pairs(company_unidentified_matched_rules) do
                        moesif_ctx.log(moesif_ctx.DEBUG, rule["name"])
                    end
                end
                concat_list(matched_rules, company_unidentified_matched_rules)
            end
        end
    end

    local regex_gov_rules = get_rules(moesif_ctx, hash_key, RuleType.REGEX, "unidentified", conf.debug)
    ---- Check if need to block request based on the regex governance rule
    if regex_gov_rules ~= nil and type(regex_gov_rules) == "table" and next(regex_gov_rules) ~= nil then
        -- Check if the governance rule regex config matches request config mapping and regex governance rules
        local regex_matched_rules = regex_config_helper.fetch_governance_rule_id_on_regex_match(moesif_ctx, regex_gov_rules, request_config_mapping, conf)
        -- Check if need to block request based on governance rule regex config
        if regex_matched_rules == nil or next(regex_matched_rules) == nil then
            if conf.debug then
                moesif_ctx.log(moesif_ctx.DEBUG, "[moesif] Skipped blocking request based on the regex governance rules")
            end
        else
            if conf.debug then
                moesif_ctx.log(moesif_ctx.DEBUG, "[moesif] Matched regex_matched_rules: ")
                for _, rule in pairs(regex_matched_rules) do
                    moesif_ctx.log(moesif_ctx.DEBUG, rule["name"])
                end
            end
            concat_list(matched_rules, regex_matched_rules)
        end
    end

    if matched_rules == nil or next(matched_rules) == nil then
        if conf.debug then
            moesif_ctx.log(moesif_ctx.DEBUG, "[moesif] No governance rule will be applied")
        end
    else
        if conf.debug then
            moesif_ctx.log(moesif_ctx.DEBUG, "[moesif] Matched rules: ")
            for _, rule in pairs(matched_rules) do
                moesif_ctx.log(moesif_ctx.DEBUG, rule["name"])
            end
        end
    end

    local resp = generate_gov_rule_response(moesif_ctx, hash_key, matched_rules, user_id_entity, company_id_entity, start_access_phase_time, conf.debug)
    if resp == nil then
        if conf.debug then
            moesif_ctx.log(moesif_ctx.DEBUG, "[moesif] No governance block response generated ")
        end
    end
end

return _M
