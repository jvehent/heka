-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at http://mozilla.org/MPL/2.0/.

-- Parse the HAProxy HTTP logs
--
-- Example Heka configuration:
--
-- [HAProxyHTTPDecoder]
-- type = "SandboxDecoder"
-- script_type = "lua"
-- filename = "lua_decoders/haproxy_http.lua"
--
-- [HAProxyHTTPDecoder.config]
-- type = "fxa-auth-server"
-- log_format = '$processname[$processid]: $sourceipaddress:$sourceport [$timestamp] $frontend_name $backend_name/$backend_server_name $tq/$tw/$tc/$tr/$tt $status_code $bytes_read $captured_request_cookie $captured_response_cookies $termination_state $actconn/$feconn/$beconn/$srv_conn/$retries $srv_queue/$backend_queue {$captured_request_headers} {$captured_response_headers} "$http_request"'
--
-- From the documentation at haproxy.1wt.eu/download/1.5/doc/configuration.txt
--
--     >>> Feb  6 12:14:14 localhost \
--           haproxy[14389]: 10.0.1.2:33317 [06/Feb/2009:12:14:14.655] http-in \
--           static/srv1 10/0/30/69/109 200 2750 - - ---- 1/1/1/1/0 0/0 {1wt.eu} \
--           {} "GET /index.html HTTP/1.1"
--
--   Field   Format                                Extract from the example above
--       1   process_name '[' pid ']:'                            haproxy[14389]:
--       2   client_ip ':' client_port                             10.0.1.2:33317
--       3   '[' accept_date ']'                       [06/Feb/2009:12:14:14.655]
--       4   frontend_name                                                http-in
--       5   backend_name '/' server_name                             static/srv1
--       6   Tq '/' Tw '/' Tc '/' Tr '/' Tt*                       10/0/30/69/109
--       7   status_code                                                      200
--       8   bytes_read*                                                     2750
--       9   captured_request_cookie                                            -
--      10   captured_response_cookie                                           -
--      11   termination_state                                               ----
--      12   actconn '/' feconn '/' beconn '/' srv_conn '/' retries*    1/1/1/1/0
--      13   srv_queue '/' backend_queue                                      0/0
--      14   '{' captured_request_headers* '}'                   {haproxy.1wt.eu}
--      15   '{' captured_response_headers* '}'                                {}
--      16   '"' http_request '"'                      "GET /index.html HTTP/1.1"

local clf = require "common_log_format"

local log_format = read_config("log_format")
local msg_type = read_config("type")

local msg = {
Timestamp = nil,
Type = msg_type,
Fields = nil
}

local grammar = clf.build_haproxy_grammar(log_format)

function process_message ()
    local log = read_message("Payload")
    local fields = grammar:match(log)
    if not fields then return -1 end

    msg.Timestamp = fields.time
    fields.time = nil

    msg.Fields = fields
    inject_message(msg)
    return 0
end
