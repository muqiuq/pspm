-- PSPM shared Lua: client keys, snapshot loading, lookups (plan §7.5, §11.3).
-- Snapshot lines: key <TAB> expires-epoch (0 = never) <TAB> value. Header lines start with '#'.
local _M = {}

local DICTS = { cleared = "pspm_cleared", banned = "pspm_banned", blocked = "pspm_blocked",
                trusted = "pspm_trusted", certs = "pspm_certs", traps = "pspm_traps", meta = "pspm_cfg" }
local state_dir = "/var/lib/pspm/state"

local bit = require "bit"
local band, lshift, rshift = bit.band, bit.lshift, bit.rshift

-- ------------------------------------------------------------------ addresses

-- IPv6 text -> eight 16-bit numbers, or nil.
local function v6_groups(ip)
    if ip:find(".", 1, true) then        -- IPv4-mapped tail (::ffff:1.2.3.4)
        local head, a, b, c, d = ip:match("^(.*:)(%d+)%.(%d+)%.(%d+)%.(%d+)$")
        if not head then return nil end
        ip = head .. string.format("%x:%x", tonumber(a) * 256 + tonumber(b), tonumber(c) * 256 + tonumber(d))
    end
    local left, right = ip, nil
    local p = ip:find("::", 1, true)
    if p then left, right = ip:sub(1, p - 1), ip:sub(p + 2) end
    local g = {}
    for x in left:gmatch("[^:]+") do g[#g + 1] = tonumber(x, 16) end
    local r = {}
    if right then for x in right:gmatch("[^:]+") do r[#r + 1] = tonumber(x, 16) end end
    if right then
        for _ = 1, 8 - #g - #r do g[#g + 1] = 0 end
        for _, x in ipairs(r) do g[#g + 1] = x end
    end
    if #g ~= 8 then return nil end
    return g
end
_M.v6_groups = v6_groups

-- The key a client is tracked under: the IPv4 address, or the IPv6 /64 as "a:b:c:d::/64".
-- Must match IP::clientKey() in PHP.
function _M.client_key(ip)
    if not ip:find(":", 1, true) then return ip end
    local g = v6_groups(ip)
    if not g then return ip end
    return string.format("%x:%x:%x:%x::/64", g[1], g[2], g[3], g[4])
end

local function v4_num(ip)
    local a, b, c, d = ip:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
    if not a then return nil end
    return ((tonumber(a) * 256 + tonumber(b)) * 256 + tonumber(c)) * 256 + tonumber(d)
end

-- The network key of ip at prefix length len, as State::cidrKey() builds it in PHP.
local function net_key(ip, len)
    if not ip:find(":", 1, true) then
        local n = v4_num(ip)
        if not n then return nil end
        local m = len == 0 and 0 or (4294967296 - 2 ^ (32 - len))
        n = n - n % (2 ^ (32 - len))
        if len == 0 then n = 0 end
        return string.format("%d.%d.%d.%d/%d", math.floor(n / 16777216) % 256, math.floor(n / 65536) % 256,
            math.floor(n / 256) % 256, n % 256, len)
    end
    local g = v6_groups(ip)
    if not g then return nil end
    if len > 64 then len = 64 end
    local out = {}
    for i = 1, 4 do
        local bits = len - (i - 1) * 16
        if bits >= 16 then out[i] = g[i]
        elseif bits <= 0 then out[i] = 0
        else out[i] = band(g[i], band(lshift(0xffff, 16 - bits), 0xffff)) end
    end
    return string.format("%x:%x:%x:%x::/%d", out[1], out[2], out[3], out[4], len)
end
_M.net_key = net_key

-- ------------------------------------------------------------------ lookups

-- Is ip inside any network of a CIDR dict (blocked, banned)? Returns the value or nil.
local function cidr_lookup(name, ip)
    local d = ngx.shared[DICTS[name]]
    if not d then return nil end
    local fam = ip:find(":", 1, true) and "6" or "4"
    local lens = ngx.shared.pspm_meta:get(name .. ":lens" .. fam)
    if not lens or lens == "" then return nil end
    for l in lens:gmatch("%d+") do
        local k = net_key(ip, tonumber(l))
        if k then
            local v = d:get(k)
            if v then return v end
        end
    end
    return nil
end

function _M.banned(ip) return cidr_lookup("banned", ip) end
function _M.trusted(ip) return cidr_lookup("trusted", ip) end
function _M.blocked(ip) return cidr_lookup("blocked", ip) end

function _M.cleared(site, key)
    if not site or site == "" then return false end
    return ngx.shared.pspm_cleared:get(site .. "|" .. key) ~= nil
end

-- A valid client certificate in scope for this site (plan §13.3). nginx verified it
-- against the CA bundle; the dict holds revocations and scopes by SHA-1 fingerprint.
function _M.cert_ok(site)
    local var = ngx.var
    if var.ssl_client_verify ~= "SUCCESS" then return false end
    local fp = var.ssl_client_fingerprint
    if not fp or fp == "" then return false end
    local v = ngx.shared.pspm_certs:get(fp)
    if v == nil then
        -- Not issued by PSPM. With strict mode, a certificate from a CA that PSPM issues
        -- with is refused; one from a trust-only CA counts (plan §13.3).
        local meta = ngx.shared.pspm_meta
        if meta:get("certs:strict") ~= "1" then return true end
        local issuer = (var.ssl_client_i_dn or ""):match("CN=([^,/]+)")
        local managed = meta:get("certs:managed") or ""
        if issuer then
            for cn in managed:gmatch("[^|]+") do if cn == issuer then return false end end
        end
        return true
    end
    if v == "revoked" then return false end
    if v == "all" then return true end
    for s in v:gmatch("[^,]+") do if s == site then return true end end
    return false
end

-- Block an address in nginx at once (trap hit, unknown-host rule). The scan job records it
-- within a minute and puts it into the firewall.
function _M.block_now(ip, why)
    local len = ip:find(":", 1, true) and 64 or 32
    local k = net_key(ip, len)
    if not k then return end
    ngx.shared.pspm_blocked:set(k, why, 86400)
    local m = ngx.shared.pspm_meta
    local fam = len == 64 and "6" or "4"
    local lens = m:get("blocked:lens" .. fam) or ""
    if not (("," .. lens .. ","):find("," .. len .. ",", 1, true)) then
        m:set("blocked:lens" .. fam, lens == "" and tostring(len) or (lens .. "," .. len))
    end
end

-- Honeypots: exact paths and prefixes per host (or "*"), cached per worker until the
-- snapshot serial changes. Returns "state:id" or nil.
local trap_serial, trap_exact, trap_prefix = nil, {}, {}
function _M.trap(host, uri)
    local serial = ngx.shared.pspm_meta:get("traps:serial")
    if serial ~= trap_serial then
        trap_exact, trap_prefix = {}, {}
        local d = ngx.shared.pspm_traps
        for _, k in ipairs(d:get_keys(0)) do
            local kind, h, path = k:match("^(%a+)|([^|]+)|(.+)$")
            local v = d:get(k)
            if kind == "exact" then trap_exact[h .. "|" .. path] = v
            elseif kind == "prefix" then trap_prefix[#trap_prefix + 1] = { h, path, v } end
        end
        trap_serial = serial
    end
    uri = (uri or ""):lower()
    host = (host or ""):lower()
    local v = trap_exact[host .. "|" .. uri] or trap_exact["*|" .. uri]
    if v then return v end
    for _, p in ipairs(trap_prefix) do
        if (p[1] == "*" or p[1] == host) and uri:sub(1, #p[2]) == p[2] then return p[3] end
    end
    return nil
end

-- Deny the request the way the site wants it (403 / 404 / close / redirect).
function _M.deny()
    local var = ngx.var
    local mode = var.pspm_deny
    if mode == "404" then return ngx.exit(404) end
    if mode == "close" or mode == "444" then return ngx.exit(444) end
    if mode == "redirect" and var.pspm_deny_url ~= "" then return ngx.redirect(var.pspm_deny_url, 302) end
    return ngx.exit(403)
end

-- ------------------------------------------------------------------ snapshots

local function read_snapshot(name)
    local f = io.open(state_dir .. "/" .. name .. ".tsv", "r")
    if not f then return nil end
    local entries, meta = {}, {}
    for line in f:lines() do
        if line:sub(1, 1) == "#" then
            local k, v = line:match("^#%s*(%S+)%s+(.*)$")
            if k then meta[k] = v end
        else
            local key, exp, val = line:match("^([^\t]+)\t(%d+)\t(.*)$")
            if key then entries[#entries + 1] = { key, tonumber(exp), val } end
        end
    end
    f:close()
    return entries, meta
end

-- Rebuild one dict in place: set the new keys first, then delete the stale ones, so no
-- grant goes missing during a sync.
function _M.load(name)
    local d = ngx.shared[DICTS[name]]
    if not d then return nil, "no dict" end
    local entries, meta = read_snapshot(name)
    if not entries then return nil, "no file" end
    local now = ngx.time()
    local keep, n, skipped = {}, 0, 0
    for _, e in ipairs(entries) do
        local key, exp, val = e[1], e[2], e[3]
        if exp == 0 or exp > now then
            local ok, err = d:set(key, val, exp == 0 and 0 or (exp - now))
            if ok then keep[key] = true; n = n + 1 else skipped = skipped + 1 end
        end
    end
    for _, k in ipairs(d:get_keys(0)) do
        if not keep[k] then d:delete(k) end
    end
    local m = ngx.shared.pspm_meta
    m:set(name .. ":serial", meta.serial or "0")
    m:set(name .. ":count", n)
    for k, v in pairs(meta) do
        if k ~= "serial" and k ~= "generated" and k ~= "pspm" then m:set(name .. ":" .. k, v) end
    end
    return n, skipped > 0 and (skipped .. " entries did not fit") or nil
end

function _M.load_all()
    local out = {}
    for name in pairs(DICTS) do
        local n, err = _M.load(name)
        out[name] = { count = n, error = err, serial = ngx.shared.pspm_meta:get(name .. ":serial") }
    end
    return out
end

-- init_by_lua: remember where the snapshots are and load them, so nginx starts with the
-- last published state even when PHP and the database are down.
function _M.init(dir)
    if dir and dir ~= "" then state_dir = dir end
    local ok, err = pcall(_M.load_all)
    if not ok then ngx.log(ngx.ERR, "pspm: loading snapshots failed: ", err) end
end

function _M.status()
    local out = {}
    local m = ngx.shared.pspm_meta
    for name in pairs(DICTS) do
        out[name] = { serial = m:get(name .. ":serial"), count = m:get(name .. ":count") }
    end
    return out
end

return _M
