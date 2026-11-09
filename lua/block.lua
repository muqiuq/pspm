-- Rewrite phase, every public server (plan §7.5): blocked addresses are refused, unless
-- they are on the LAN, cleared for this site, or present a valid certificate in scope.
-- Private addresses always pass.
local pspm = require "pspm"
local var = ngx.var

if var.pspm_private == "1" then return end
local ip = var.remote_addr
if not pspm.blocked(ip) then return end
if var.pspm_lan == "1" then return end
if pspm.cleared(var.pspm_site, pspm.client_key(ip)) then return end
if pspm.cert_ok(var.pspm_site) then return end
var.pspm_outcome = "blocked"
return ngx.exit(444)
