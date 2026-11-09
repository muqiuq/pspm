-- Access phase (plan §7.5): a banned address is refused; then the conditions of the
-- route (or else the site) in $pspm_allow are checked. Shared-dict lookups only.
local pspm = require "pspm"
local var = ngx.var

local ip = var.remote_addr
if pspm.banned(ip) and var.pspm_private ~= "1" then
    var.pspm_outcome = "banned"
    return ngx.exit(403)
end

local allow = var.pspm_allow or ""
local key = pspm.client_key(ip)
for cond in allow:gmatch("[^,]+") do
    if cond == "public" then var.pspm_outcome = "public"; return end
    if cond == "lan" and var.pspm_lan == "1" then var.pspm_outcome = "lan"; return end
    if cond == "cleared" and pspm.cleared(var.pspm_site, key) then var.pspm_outcome = "cleared"; return end
    if cond == "cert" and pspm.cert_ok(var.pspm_site) then var.pspm_outcome = "cert"; return end
end

var.pspm_outcome = "denied"
return pspm.deny()
