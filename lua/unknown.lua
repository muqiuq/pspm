-- Rewrite phase of the catch-all servers (plan §8.2, §15.6): the UI by IP for private
-- addresses (while no admin host name is in effect); everything else is closed, and five
-- requests within an hour for host names no site serves block the address.
local pspm = require "pspm"
local var = ngx.var
local ip = var.remote_addr

if var.pspm_private ~= "1" and pspm.blocked(ip) then
    var.pspm_outcome = "blocked"
    return ngx.exit(444)
end
if var.pspm_ui_by_ip == "1" and var.pspm_ip_ui == "1" then return end
var.pspm_outcome = "unknown-host"
if var.pspm_private == "1" or pspm.trusted(ip) then return ngx.exit(444) end
local cfg = ngx.shared.pspm_cfg
local threshold = tonumber(cfg:get("unknown_threshold") or "5") or 5
if threshold > 0 then
    local window = tonumber(cfg:get("unknown_window") or "3600") or 3600
    local n = ngx.shared.pspm_unknown:incr(pspm.client_key(ip), 1, 0, window)
    if n and n >= threshold then
        pspm.block_now(ip, "unknown-host")
        var.pspm_outcome = "unknown-block"
    end
end
return ngx.exit(444)
