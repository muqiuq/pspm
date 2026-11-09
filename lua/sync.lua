-- GET /pspm-sync on 127.0.0.1:9080: reload the dicts from the snapshot files in place.
-- ?status=1 only reports what is loaded (serials and counts).
local pspm = require "pspm"

if ngx.var.remote_addr ~= "127.0.0.1" then return ngx.exit(403) end

-- Small JSON encoder for this flat structure (no lua-cjson dependency).
local function enc(v)
    local t = type(v)
    if t == "table" then
        local parts = {}
        for k, x in pairs(v) do parts[#parts + 1] = string.format("%q:%s", tostring(k), enc(x)) end
        table.sort(parts)
        return "{" .. table.concat(parts, ",") .. "}"
    elseif t == "number" then return tostring(v)
    elseif t == "nil" then return "null"
    elseif t == "boolean" then return v and "true" or "false"
    end
    return string.format("%q", tostring(v)):gsub("\\\n", "\\n")
end

local args = ngx.req.get_uri_args()
local out = args.status and { loaded = pspm.status() } or { synced = pspm.load_all() }
ngx.header["Content-Type"] = "application/json"
ngx.say(enc(out))
