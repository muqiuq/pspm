-- Rewrite phase, every public site server (plan §7.5, §15.5): blocked addresses are
-- refused unless they are on the LAN, cleared for this site, or present a valid
-- certificate in scope; an untrusted address that hits an active honeypot is blocked on
-- the spot. Private addresses always pass.
local pspm = require "pspm"
local var = ngx.var

if var.pspm_private == "1" or ngx.req.is_internal() then return end
local ip = var.remote_addr
local exempt = nil
local function is_exempt()
    if exempt == nil then
        exempt = var.pspm_lan == "1" or pspm.cleared(var.pspm_site, pspm.client_key(ip)) or pspm.cert_ok(var.pspm_site)
            or pspm.trusted(ip) ~= nil
    end
    return exempt
end

if pspm.blocked(ip) and not is_exempt() then
    var.pspm_outcome = "blocked"
    return ngx.exit(444)
end

if ngx.shared.pspm_cfg:get("traps_enabled") ~= "0" then
    local hit = pspm.trap(var.host, var.uri)
    if hit and not is_exempt() then
        local state, id = hit:match("^(%a+):(%d+)$")
        if state == "active" then
            pspm.block_now(ip, "trap")
            var.pspm_outcome = "trap:" .. id
            return ngx.exit(444)
        end
        var.pspm_outcome = "trap-shadow:" .. (id or "?")
    end
end
