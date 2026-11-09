-- Access phase (plan §7.5, §12.3): a banned address is refused; then the conditions of
-- the route (or else the site) in $pspm_allow are checked, and the sign-in at the site's
-- provider: "alternative" (OR) or "required" (AND). Shared-dict lookups and, for sign-in,
-- one local subrequest to oauth2-proxy.
local pspm = require "pspm"
local var = ngx.var

-- Internal redirects (the PSPM error pages) were checked as the original request; running
-- again would overwrite the outcome the security log records.
if ngx.req.is_internal() then return end

local ip = var.remote_addr
if var.pspm_private ~= "1" and pspm.banned(ip) then
    var.pspm_outcome = "banned"
    return ngx.exit(403)
end

-- Session cookies of the sign-in never reach a backend: they are valid for the whole cookie
-- domain, so a backend that saw one could replay it against other sites (plan §12.4).
local function strip_signin_cookies()
    local ck = var.http_cookie
    if not ck or not ck:find("_pspm_", 1, true) then return end
    local keep = {}
    for part in ck:gmatch("[^;]+") do
        local p = part:gsub("^%s+", "")
        if p:sub(1, 6) ~= "_pspm_" then keep[#keep + 1] = p end
    end
    if #keep > 0 then ngx.req.set_header("Cookie", table.concat(keep, "; ")) else ngx.req.clear_header("Cookie") end
end

local function wants_html()
    local m = ngx.req.get_method()
    if m ~= "GET" and m ~= "HEAD" then return false end
    local accept = var.http_accept or ""
    return accept == "" or accept:find("text/html", 1, true) ~= nil
end

-- The sign-in check: 202 lets in (identity in variables for the headers), 401 sends a
-- browser to the sign-in host, 403 refuses, anything else fails closed with 503.
local function signin()
    local res = ngx.location.capture("/.pspm/signin/auth", { method = ngx.HTTP_GET, args = var.pspm_signin_args or "" })
    local st = res.status
    if st == 202 or st == 200 then
        local h = res.header
        var.pspm_user = h["X-Auth-Request-User"] or ""
        var.pspm_email = h["X-Auth-Request-Email"] or ""
        var.pspm_groups = h["X-Auth-Request-Groups"] or ""
        var.pspm_puser = h["X-Auth-Request-Preferred-Username"] or ""
        var.pspm_token = h["X-Auth-Request-Access-Token"] or ""
        var.pspm_outcome = "signin"
        strip_signin_cookies()
        return
    end
    if st == 401 then
        var.pspm_outcome = "signin-needed"
        if wants_html() or var.pspm_signin_nb401 == "0" then
            local back = "https://" .. var.host .. var.request_uri
            return ngx.redirect("https://" .. var.pspm_signin_host .. "/oauth2/start?rd=" .. ngx.escape_uri(back), 302)
        end
        return ngx.exit(401)
    end
    if st == 403 then
        var.pspm_outcome = "signin-denied"
        return ngx.exit(403)
    end
    ngx.log(ngx.ERR, "pspm: sign-in check answered ", st, " (oauth2-proxy down?)")
    var.pspm_outcome = "signin-unavailable"
    return ngx.exit(503)
end

local allow = var.pspm_allow or ""
local key = pspm.client_key(ip)
local met = nil
for cond in allow:gmatch("[^,]+") do
    if cond == "public" then met = "public"
    elseif cond == "lan" and var.pspm_lan == "1" then met = "lan"
    elseif cond == "cleared" and pspm.cleared(var.pspm_site, key) then met = "cleared"
    elseif cond == "cert" and pspm.cert_ok(var.pspm_site) then met = "cert"
    end
    if met then break end
end

local mode = var.pspm_signin or "none"
if mode == "required" then
    if not met then var.pspm_outcome = "denied"; return pspm.deny() end
    return signin()
end
if met then
    var.pspm_outcome = met
    strip_signin_cookies()
    return
end
if mode == "alternative" then return signin() end
var.pspm_outcome = "denied"
return pspm.deny()
