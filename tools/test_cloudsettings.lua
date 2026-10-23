-- Run: lua5.4 tools/test_cloudsettings.lua
-- Backend for the Cloud Saves tab. Reads/writes the CloudRedirect file contract
-- (~/.config/CloudRedirect/config.json + tokens_<provider>.json) directly in
-- Lua — no hook --cli, no flatpak. Also the OAuth2 authorization-code + PKCE
-- flow ported from CloudRedirect's OAuthService.cs. All RPCs return JSON
-- strings (the callServerMethod convention). Pure helpers + a fake-socket /
-- fake-http state machine keep it host-testable.
package.path = "lua/?.lua;" .. package.path
local cs = require("cloudsettings")
local json = require("json")
local sha256 = require("sha256")
local b64 = require("b64")

local function ok(c, m) if not c then error("FAIL: " .. (m or "")) end end
local function eq(g, w, m)
  if g ~= w then error("FAIL: " .. (m or "") .. " (got=" .. tostring(g) ..
    " want=" .. tostring(w) .. ")") end
end
local function tmpfile(contents)
  local p = os.tmpname()
  local f = assert(io.open(p, "wb")); f:write(contents or ""); f:close()
  return p
end

-- ── PKCE S256 challenge = base64url(sha256(verifier)), no padding ───────────
do
  local verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
  local want = (b64.encode(sha256.digest(verifier))
                 :gsub("+", "-"):gsub("/", "_"):gsub("=", ""))
  eq(cs.pkce_challenge(verifier), want, "pkce challenge")
  ok(not cs.pkce_challenge(verifier):find("="), "no padding in challenge")
  ok(not cs.pkce_challenge(verifier):find("[+/]"), "url-safe alphabet only")
end

-- ── auth URL carries the required OAuth params, url-encoded ─────────────────
do
  local u = cs.build_auth_url("gdrive", "http://localhost:1234/callback", "STATE1", "CHAL1")
  ok(u:find("https://accounts.google.com/o/oauth2/v2/auth", 1, true), "gdrive auth endpoint")
  ok(u:find("response_type=code", 1, true), "response_type")
  ok(u:find("client_id=1072944905499", 1, true), "gdrive client id")
  ok(u:find("code_challenge=CHAL1", 1, true), "challenge")
  ok(u:find("code_challenge_method=S256", 1, true), "S256")
  ok(u:find("state=STATE1", 1, true), "state")
  ok(u:find("access_type=offline", 1, true), "gdrive offline")
  ok(u:find("prompt=consent", 1, true), "consent")
  -- redirect uri percent-encoded (":" and "/" escaped)
  ok(u:find("redirect_uri=http%%3A%%2F%%2Flocalhost%%3A1234%%2Fcallback", 1, false),
    "redirect uri encoded")

  local o = cs.build_auth_url("onedrive", "http://localhost:53682/", "S2", "C2")
  ok(o:find("login.microsoftonline.com", 1, true), "onedrive endpoint")
  ok(o:find("client_id=b15665d9", 1, true), "onedrive client id")
  ok(not o:find("access_type", 1, true), "onedrive has no access_type")
end

-- ── token exchange request body (form-encoded) ──────────────────────────────
do
  local body = cs.token_request_body("gdrive", "AUTHCODE", "http://localhost:9/callback", "VER")
  ok(body:find("grant_type=authorization_code", 1, true), "grant type")
  ok(body:find("code=AUTHCODE", 1, true), "code")
  ok(body:find("code_verifier=VER", 1, true), "verifier")
  ok(body:find("client_secret=", 1, true), "client secret present")
  ok(not body:find("scope=", 1, true), "gdrive body omits scope")

  local ob = cs.token_request_body("onedrive", "C", "http://localhost:53682/", "V")
  ok(ob:find("scope=", 1, true), "onedrive body includes scope")
end

-- ── parse the OAuth callback HTTP request line ──────────────────────────────
do
  local code, state = cs.parse_callback("GET /callback?code=abc123&state=xyz HTTP/1.1")
  eq(code, "abc123", "parsed code")
  eq(state, "xyz", "parsed state")
  -- order-independent + percent-decoding
  local c2, s2 = cs.parse_callback("GET /?state=s%20p&code=a%2Bb HTTP/1.1")
  eq(c2, "a+b", "url-decoded code")
  eq(s2, "s p", "url-decoded state")
  -- error param, no code
  local c3, s3, err = cs.parse_callback("GET /callback?error=access_denied&state=x HTTP/1.1")
  eq(c3, nil, "no code on error")
  eq(err, "access_denied", "parsed error")
end

-- ── read_config: missing file yields defaults (provider=local) ──────────────
do
  local cfg = cs.read_config("/nonexistent/nope.json")
  eq(cfg.provider, "local", "default provider local")
end

-- ── status: no token file => not authenticated ─────────────────────────────
do
  local p = tmpfile('{"provider":"gdrive"}')
  local st = json.decode(cs.status(p))
  eq(st.success, true, "status success")
  eq(st.provider, "gdrive", "status provider")
  eq(st.authenticated, false, "not authenticated without token")
  os.remove(p)
end

-- ── status: token file with refresh_token => authenticated ─────────────────
do
  local dir = os.tmpname(); os.remove(dir); assert(os.execute("mkdir -p '" .. dir .. "'"))
  local cfgp = dir .. "/config.json"
  local f = io.open(cfgp, "wb"); f:write('{"provider":"gdrive"}'); f:close()
  local tf = io.open(dir .. "/tokens_gdrive.json", "wb")
  tf:write('{"refresh_token":"RT","access_token":"AT","expires_at":9999999999}'); tf:close()
  local st = json.decode(cs.status(cfgp))
  eq(st.authenticated, true, "authenticated with refresh token")
  os.execute("rm -rf '" .. dir .. "'")
end

-- ── set_provider writes provider, preserves other keys ──────────────────────
do
  local p = tmpfile('{"provider":"local","upload_inflight_mb":24,"notifications_enabled":true}')
  local res = json.decode(cs.set_provider(p, "onedrive"))
  eq(res.success, true, "set_provider success")
  local cfg = cs.read_config(p)
  eq(cfg.provider, "onedrive", "provider written")
  eq(cfg.upload_inflight_mb, 24, "unrelated int key preserved")
  eq(cfg.notifications_enabled, true, "unrelated bool key preserved")
  os.remove(p)
end

-- ── set_provider rejects an unknown provider ────────────────────────────────
do
  local p = tmpfile('{"provider":"local"}')
  local res = json.decode(cs.set_provider(p, "dropbox"))
  eq(res.success, false, "unknown provider rejected")
  eq(cs.read_config(p).provider, "local", "config unchanged")
  os.remove(p)
end

-- ── set_provider creates a default config when the file is absent ───────────
do
  local dir = os.tmpname(); os.remove(dir); assert(os.execute("mkdir -p '" .. dir .. "'"))
  local cfgp = dir .. "/config.json"
  local res = json.decode(cs.set_provider(cfgp, "gdrive"))
  eq(res.success, true, "creates config when missing")
  eq(cs.read_config(cfgp).provider, "gdrive", "provider persisted to new file")
  os.execute("rm -rf '" .. dir .. "'")
end

-- ── set_toggle only accepts the two stats keys ──────────────────────────────
do
  local p = tmpfile('{"provider":"gdrive"}')
  eq(json.decode(cs.set_toggle(p, "sync_achievements", true)).success, true, "achievements ok")
  eq(json.decode(cs.set_toggle(p, "sync_playtime", true)).success, true, "playtime ok")
  eq(cs.read_config(p).sync_achievements, true, "achievements persisted")
  eq(cs.read_config(p).sync_playtime, true, "playtime persisted")
  -- schema_fetch and arbitrary keys are rejected (never written)
  eq(json.decode(cs.set_toggle(p, "schema_fetch", false)).success, false, "schema_fetch rejected")
  eq(json.decode(cs.set_toggle(p, "stats_sync_enabled", false)).success, false, "master rejected")
  eq(cs.read_config(p).schema_fetch, nil, "schema_fetch not written")
  os.remove(p)
end

-- ── sign_out deletes the token file and resets provider to local ────────────
do
  local dir = os.tmpname(); os.remove(dir); assert(os.execute("mkdir -p '" .. dir .. "'"))
  local cfgp = dir .. "/config.json"
  local f = io.open(cfgp, "wb"); f:write('{"provider":"gdrive"}'); f:close()
  local tp = dir .. "/tokens_gdrive.json"
  local tf = io.open(tp, "wb"); tf:write('{"refresh_token":"RT"}'); tf:close()
  local res = json.decode(cs.sign_out(cfgp, "gdrive"))
  eq(res.success, true, "sign_out success")
  eq(cs.read_config(cfgp).provider, "local", "provider reset to local")
  ok(io.open(tp, "rb") == nil, "token file deleted")
  os.execute("rm -rf '" .. dir .. "'")
end

-- ── authorize/auth_poll state machine with fake socket + http ───────────────
-- Fake a listener whose accept() first times out (waiting), then returns a
-- client delivering the OAuth redirect. Fake http returns a token JSON.
do
  local dir = os.tmpname(); os.remove(dir); assert(os.execute("mkdir -p '" .. dir .. "'"))
  local cfgp = dir .. "/config.json"

  local sent_response = false
  local captured_state
  local function make_client(reqline)
    return {
      receive = function(_, pat) return reqline end,
      send = function(_, data) sent_response = true; return #data end,
      close = function() end,
      settimeout = function() end,
    }
  end

  local accept_calls = 0
  local fake_listener = {
    settimeout = function() end,
    getsockname = function() return "127.0.0.1", 45999 end,
    bind = function() return 1 end,
    listen = function() return 1 end,
    close = function() end,
    accept = function()
      accept_calls = accept_calls + 1
      if accept_calls == 1 then return nil, "timeout" end
      -- second poll: deliver the redirect with the state we generated
      return make_client("GET /callback?code=THECODE&state=" .. captured_state .. " HTTP/1.1\r\n")
    end,
  }
  local fake_socket = { tcp = function() return fake_listener end }

  local opened
  local fake_http = {
    post = function(url, body, opts)
      ok(url:find("oauth2.googleapis.com/token", 1, true), "posts to token endpoint")
      ok(body:find("code=THECODE", 1, true), "posts the received code")
      return { status = 200,
        body = '{"access_token":"AT","refresh_token":"RT","expires_in":3600}' }
    end,
  }

  local seq = 0
  local deps = {
    socket = fake_socket,
    http = fake_http,
    now = function() return 1000 end,
    open_url = function(u) opened = u end,
    gen_random = function(n) seq = seq + 1; return "RAND" .. seq .. "_" .. n end,
  }

  local a = json.decode(cs.authorize(cfgp, "gdrive", deps))
  eq(a.status, "waiting", "authorize returns waiting")
  ok(a.auth_url and a.auth_url:find("accounts.google.com", 1, true), "authorize returns the auth url")
  -- authorize no longer opens the browser itself (the frontend drives a
  -- focus-carrying open via Steam); the URL is returned for it to use.
  eq(opened, nil, "authorize does not open the browser itself")
  -- recover the state we generated for the callback the fake will echo back
  captured_state = a.auth_url:match("state=([^&]+)")
  ok(captured_state ~= nil, "state captured from auth url")

  local p1 = json.decode(cs.auth_poll(deps))
  eq(p1.status, "waiting", "first poll still waiting (accept timeout)")

  local p2 = json.decode(cs.auth_poll(deps))
  eq(p2.status, "done", "second poll completes")
  eq(p2.authenticated, true, "authenticated after exchange")
  ok(sent_response, "browser got the closing response")

  -- OAuth completion is staged: the live hook/config stays untouched until the
  -- user chooses Save and restart.
  ok(io.open(dir .. "/tokens_gdrive.json", "rb") == nil,
    "OAuth does not replace the live token before apply")
  eq(cs.read_config(cfgp).provider, "local", "provider stays local before apply")
  eq(p2.pending, true, "completed OAuth reports a pending credential")

  local restarted = false
  local applied = json.decode(cs.apply_and_restart(cfgp, {
    provider = "gdrive",
    sync_activity = true,
  }, {
    restart = function()
      local live = cs.read_config(cfgp)
      eq(live.provider, "gdrive", "config is committed before restart")
      restarted = true
      return true
    end,
  }))
  eq(applied.success, true, "apply and restart succeeds")
  eq(restarted, true, "restart is requested once")

  local tf = io.open(dir .. "/tokens_gdrive.json", "rb")
  ok(tf ~= nil, "staged token is promoted on apply")
  local tok = json.decode(tf:read("*a")); tf:close()
  eq(tok.refresh_token, "RT", "refresh token stored")
  eq(tok.access_token, "AT", "access token stored")
  eq(tok.expires_at, 1000 + 3600, "expires_at = now + expires_in")
  local applied_cfg = cs.read_config(cfgp)
  eq(applied_cfg.provider, "gdrive", "provider set on apply")
  eq(applied_cfg.sync_achievements, true, "unified activity enables achievements")
  eq(applied_cfg.sync_playtime, true, "unified activity enables playtime")
  eq(applied_cfg.stats_sync_enabled, true, "unified activity enables the upstream master gate")
  eq(applied_cfg.token_paths.gdrive, dir .. "/tokens_gdrive.json",
    "apply registers the exact provider token path")

  -- A failed restart rolls every committed file back, including sign-out.
  local rolled = json.decode(cs.apply_and_restart(cfgp, {
    provider = "local",
    sync_activity = false,
    sign_out_provider = "gdrive",
  }, { restart = function() return false, "restart failed" end }))
  eq(rolled.success, false, "restart failure is reported")
  eq(cs.read_config(cfgp).provider, "gdrive", "provider rolls back after restart failure")
  eq(cs.read_config(cfgp).sync_achievements, true, "activity rolls back after restart failure")
  ok(io.open(dir .. "/tokens_gdrive.json", "rb") ~= nil,
    "signed-out token is restored after restart failure")

  os.execute("rm -rf '" .. dir .. "'")
end


-- The upstream master gate participates in the unified activity setting.
do
  local p = tmpfile('{"provider":"local","stats_sync_enabled":false,"sync_achievements":true,"sync_playtime":true}')
  local st = json.decode(cs.status(p))
  eq(st.sync_activity, false, "disabled upstream master gate reports activity off")
  os.remove(p)
end

-- ── auth_poll reports timeout past the deadline ─────────────────────────────
do
  local dir = os.tmpname(); os.remove(dir); assert(os.execute("mkdir -p '" .. dir .. "'"))
  local cfgp = dir .. "/config.json"
  local fake_listener = {
    settimeout = function() end,
    getsockname = function() return "127.0.0.1", 46000 end,
    bind = function() return 1 end, listen = function() return 1 end,
    close = function() end,
    accept = function() return nil, "timeout" end,
  }
  local t = 1000
  local deps = {
    socket = { tcp = function() return fake_listener end },
    http = { post = function() error("should not exchange") end },
    now = function() return t end,
    open_url = function() end,
    gen_random = function(n) return "R" .. n end,
  }
  json.decode(cs.authorize(cfgp, "onedrive", deps))
  eq(json.decode(cs.auth_poll(deps)).status, "waiting", "waiting before deadline")
  t = 1000 + 10 * 60 -- 10 minutes later, well past the 5-min timeout
  eq(json.decode(cs.auth_poll(deps)).status, "timeout", "timeout past deadline")
  -- a poll with no pending auth is idle
  eq(json.decode(cs.auth_poll(deps)).status, "idle", "idle when nothing pending")
  os.execute("rm -rf '" .. dir .. "'")
end

-- ── register() + the real RPC dispatch path (Millennium arg convention) ─────
-- The frontend sends a SINGLE {json: JSON.stringify(payload)} arg; the
-- dispatcher (rpc.lua) sorts keys alphabetically and passes their VALUES
-- positionally, so the registered wrapper receives the json STRING and must
-- decode it. This guards the "unknown provider" regression where the wrapper
-- wrongly treated the positional string as an args table.
do
  local rpc = require("rpc")
  local p = tmpfile('{"provider":"local"}')
  local registry = {}
  cs.register(registry, p)

  local ok1, res1 = rpc.dispatch(registry.LumenCloudSetProvider,
    { json = json.encode({ provider = "onedrive" }) })
  ok(ok1, "SetProvider dispatch did not error")
  eq(json.decode(res1).success, true, "SetProvider via dispatch succeeds")
  eq(cs.read_config(p).provider, "onedrive", "provider persisted via dispatch")

  local ok2, res2 = rpc.dispatch(registry.LumenCloudSetToggle,
    { json = json.encode({ key = "sync_playtime", value = true }) })
  ok(ok2, "SetToggle dispatch did not error")
  eq(json.decode(res2).success, true, "SetToggle via dispatch succeeds")
  eq(cs.read_config(p).sync_playtime, true, "toggle persisted via dispatch")

  local _, res3 = rpc.dispatch(registry.LumenCloudStatus, {})
  eq(json.decode(res3).provider, "onedrive", "Status via dispatch reads provider")

  local _, res4 = rpc.dispatch(registry.LumenCloudSignOut,
    { json = json.encode({ provider = "onedrive" }) })
  eq(json.decode(res4).success, true, "SignOut via dispatch succeeds")
  eq(cs.read_config(p).provider, "local", "SignOut reset provider via dispatch")
  os.remove(p)
end

-- ── non-OAuth providers: folder, R2 and generic S3 ─────────────────────────
do
  local dir = os.tmpname(); os.remove(dir); assert(os.execute("mkdir -p '" .. dir .. "'"))
  local cfgp = dir .. "/config.json"
  local f = assert(io.open(cfgp, "wb")); f:write('{"provider":"local","keep":17}'); f:close()

  local probed
  local r2 = json.decode(cs.apply_and_restart(cfgp, {
    provider = "r2",
    sync_activity = true,
    credentials = {
      account_id = "acct",
      access_key_id = "access",
      secret_access_key = "secret",
      bucket = "bucket",
      key_prefix = "cloudredirect/",
    },
  }, {
    probe = function(provider) probed = provider; return true end,
    restart = function() return true end,
  }))
  eq(r2.success, true, "R2 draft applies")
  eq(probed, "r2", "R2 bucket is probed before restart")
  local r2path = dir .. "/r2_credentials.json"
  local rf = assert(io.open(r2path, "rb")); local r2cred = json.decode(rf:read("*a")); rf:close()
  eq(r2cred.account_id, "acct", "R2 account stored")
  eq(r2cred.secret_access_key, "secret", "R2 secret stored")
  local r2cfg = cs.read_config(cfgp)
  eq(r2cfg.provider, "r2", "R2 becomes active")
  eq(r2cfg.token_paths.r2, r2path, "R2 credential path registered")
  eq(r2cfg.keep, 17, "unrelated config survives R2 apply")
  local r2status = json.decode(cs.status(cfgp))
  eq(r2status.authenticated, true, "valid R2 credentials are recognized")
  eq(r2status.providers.r2.settings.account_id, "acct", "R2 non-secret fields are exposed")
  eq(r2status.providers.r2.settings.has_secret, true, "R2 reports a stored secret")
  eq(r2status.providers.r2.settings.secret_access_key, nil, "R2 secret is never exposed")

  local before = assert(io.open(cfgp, "rb")):read("*a")
  local s3fail = json.decode(cs.apply_and_restart(cfgp, {
    provider = "s3",
    sync_activity = false,
    credentials = {
      access_key_id = "s3-access",
      secret_access_key = "s3-secret",
      bucket = "saves",
      endpoint = "minio.example.test:9000",
      region = "us-east-1",
    },
  }, {
    probe = function(provider) eq(provider, "s3", "S3 probe provider"); return false, "unreachable" end,
    restart = function() error("must not restart after a failed probe") end,
  }))
  eq(s3fail.success, false, "failed S3 connection prevents apply")
  eq(assert(io.open(cfgp, "rb")):read("*a"), before, "failed S3 probe rolls config back")
  ok(io.open(dir .. "/s3_credentials.json", "rb") == nil,
    "failed S3 probe removes the new credential file")

  local s3ok = json.decode(cs.apply_and_restart(cfgp, {
    provider = "s3",
    sync_activity = false,
    credentials = {
      access_key_id = "s3-access", secret_access_key = "s3-secret",
      bucket = "saves", endpoint = "minio.example.test:9000", region = "us-east-1",
      key_prefix = "cloudredirect/", sign_payload = true,
      allow_insecure_http = true, allow_insecure_tls = true,
      ca_cert_path = "/etc/ssl/private-minio-ca.pem",
    },
  }, {
    probe = function(provider) eq(provider, "s3", "S3 success probe provider"); return true end,
    restart = function() return true end,
  }))
  eq(s3ok.success, true, "S3-compatible draft applies")
  local sf = assert(io.open(dir .. "/s3_credentials.json", "rb"))
  local s3cred = json.decode(sf:read("*a")); sf:close()
  eq(s3cred.endpoint, "minio.example.test:9000", "S3 endpoint is stored")
  eq(s3cred.sign_payload, true, "S3 payload signing option is stored")
  eq(s3cred.allow_insecure_http, true, "S3 HTTP transport option is stored")
  eq(s3cred.allow_insecure_tls, true, "S3 TLS transport option is stored")
  eq(s3cred.ca_cert_path, "/etc/ssl/private-minio-ca.pem", "S3 CA path is stored")
  local s3status = json.decode(cs.status(cfgp)).providers.s3.settings
  eq(s3status.has_secret, true, "S3 status reports its stored secret without exposing it")
  eq(s3status.secret_access_key, nil, "S3 status never exposes the secret")
  eq(s3status.sign_payload, true, "S3 status returns advanced signing state")

  local folder = dir .. "/network-saves"
  local folder_result = json.decode(cs.apply_and_restart(cfgp, {
    provider = "folder",
    sync_activity = false,
    sync_folder_path = folder,
  }, { restart = function() return true end }))
  eq(folder_result.success, true, "custom folder applies")
  local folder_cfg = cs.read_config(cfgp)
  eq(folder_cfg.provider, "folder", "custom folder becomes active")
  eq(folder_cfg.sync_folder_path, folder, "custom folder path is persisted")
  eq(json.decode(cs.status(cfgp)).authenticated, true, "custom folder is ready")

  -- Provider switches can copy the old provider before committing the restart.
  local migrated
  local switched = json.decode(cs.apply_and_restart(cfgp, {
    provider = "r2",
    sync_activity = false,
    credentials = {
      account_id = "acct2", access_key_id = "access2",
      secret_access_key = "secret2", bucket = "bucket2",
    },
    migrate = true,
  }, {
    probe = function() return true end,
    migrate = function(source, destination)
      migrated = source .. ":" .. destination
      return true, { migrated = 4, skipped = 2, failed = 0 }
    end,
    restart = function() return true end,
  }))
  eq(switched.success, true, "provider switch with migration applies")
  eq(migrated, "folder:r2", "migration runs from the applied provider to the draft provider")

  local stable = assert(io.open(cfgp, "rb")):read("*a")
  local migration_failed = json.decode(cs.apply_and_restart(cfgp, {
    provider = "s3",
    sync_activity = false,
    credentials = {
      access_key_id = "sa", secret_access_key = "ss", bucket = "sb",
      endpoint = "s3.example", region = "us-east-1",
    },
    migrate = true,
  }, {
    probe = function() return true end,
    migrate = function() return false, "one file failed" end,
    restart = function() error("must not restart after migration failure") end,
  }))
  eq(migration_failed.success, false, "migration failure prevents provider switch")
  eq(assert(io.open(cfgp, "rb")):read("*a"), stable,
    "migration failure restores the applied configuration")

  os.execute("rm -rf '" .. dir .. "'")
end

-- ── remote apps: provider/auth gating + structured cloud statistics ─────────
do
  ok(type(cs.remote_apps) == "function", "structured remote apps API is available")

  -- local provider => no remote enumeration, empty appids (quietly).
  local p = tmpfile('{"provider":"local"}')
  local r = json.decode(cs.remote_apps(p, 1, {}))
  eq(r.success, true, "local provider remote ok")
  eq(#r.appids, 0, "local provider has no remote appids")
  eq(#r.apps, 0, "local provider has no structured remote apps")
  os.remove(p)

  -- gdrive but no token file => not_authenticated.
  local dir = os.tmpname(); os.remove(dir); assert(os.execute("mkdir -p '" .. dir .. "'"))
  local cfgp = dir .. "/config.json"
  local f = io.open(cfgp, "wb"); f:write('{"provider":"gdrive"}'); f:close()
  local na = json.decode(cs.remote_apps(cfgp, 1052518393, {}))
  eq(na.success, false, "gdrive without token fails")
  eq(na.reason, "not_authenticated", "reason is not_authenticated")

  -- gdrive with a token => local apps skip metadata and remote-only apps return
  -- logical statistics from canonical state.
  local tf = io.open(dir .. "/tokens_gdrive.json", "wb")
  tf:write('{"refresh_token":"RT","access_token":"AT","expires_at":9999999999}'); tf:close()
  local calls = {}
  local fake = {
    post = function() return { status = 200, body = '{"access_token":"ATOK","expires_in":3599}' } end,
    get = function(url)
      calls[#calls + 1] = url
      if url:find("STATEID", 1, true) and url:find("alt=media", 1, true) then
        return { status = 200, body = json.encode({ files = {
          ["remote.sav"] = { size = 5423 },
        } }) }
      elseif url:find("REMOTEID", 1, true) then
        return { status = 200, body = json.encode({ files = {
          { id = "STATEID", name = "state.cloudredirect", mimeType = "application/json" },
        } }) }
      elseif url:find("CloudRedirect", 1, true) and url:find("root", 1, true) then
        return { status = 200, body = json.encode({ files = { { id = "ROOTID", name = "CloudRedirect",
          mimeType = "application/vnd.google-apps.folder" } } }) }
      elseif url:find("1052518393", 1, true) then
        return { status = 200, body = json.encode({ files = { { id = "ACCTID", name = "1052518393",
          mimeType = "application/vnd.google-apps.folder" } } }) }
      elseif url:find("ACCTID", 1, true) then
        return { status = 200, body = json.encode({ files = {
          { id = "LOCALID", name = "250900", mimeType = "application/vnd.google-apps.folder" },
          { id = "REMOTEID", name = "311690", mimeType = "application/vnd.google-apps.folder" },
        } }) }
      end
      return { status = 404, body = "{}" }
    end,
  }
  local rr = json.decode(cs.remote_apps(cfgp, 1052518393, { 250900 }, { http = fake }))
  eq(rr.success, true, "gdrive with token succeeds")
  eq(rr.apps[1].appid, 250900, "structured local app returned")
  eq(rr.apps[2].appid, 311690, "structured remote-only app returned")
  eq(rr.apps[2].files, 1, "remote logical file count returned")
  eq(rr.apps[2].size, 5423, "remote logical byte size returned")
  eq(rr.appids[1], 250900, "compatibility local appid returned")
  eq(rr.appids[2], 311690, "compatibility remote appid returned")

  -- The old presence-only API remains cheap: it must not read per-app metadata.
  calls = {}
  local presence = json.decode(cs.remote_appids(cfgp, 1052518393, { http = fake }))
  eq(presence.success, true, "presence-only compatibility API succeeds")
  eq(presence.appids[2], 311690, "presence-only API returns remote appids")
  for _, url in ipairs(calls) do
    ok(not url:find("LOCALID", 1, true) and not url:find("REMOTEID", 1, true),
      "presence-only API skips per-app metadata")
  end

  -- The UI-facing RPC must stay on the fast presence-only path. Reading every
  -- remote-only app's metadata makes the settings list take tens of seconds.
  local cr = require("cloudremote")
  local old_list_apps = cr.list_apps
  local old_list_appids = cr.list_appids
  local presence_account
  cr.list_apps = function()
    error("UI RPC must not fetch per-app metadata")
  end
  cr.list_appids = function(provider, refresh_token, account)
    presence_account = account
    return { 250900, 311690 }
  end
  local registry = {}
  cs.register(registry, cfgp)
  local rpc = require("rpc")
  local dispatched, raw = rpc.dispatch(registry.LumenCloudRemoteApps, {
    json = json.encode({ account = 1052518393, local_appids = { 250900 } }),
  })
  cr.list_apps = old_list_apps
  cr.list_appids = old_list_appids
  ok(dispatched, "presence-only remote RPC dispatch succeeds")
  eq(presence_account, 1052518393, "registered RPC forwards the selected account")
  eq(json.decode(raw).appids[2], 311690, "registered RPC returns remote appids")
  ok(json.decode(raw).apps == nil, "registered RPC omits expensive remote metadata")
  os.execute("rm -rf '" .. dir .. "'")
end

-- ── remote listing for R2/S3 and custom-folder providers ────────────────────
do
  local dir = os.tmpname(); os.remove(dir); assert(os.execute("mkdir -p '" .. dir .. "'"))
  local cli = dir .. "/cloud_redirect_cli"
  local cf = assert(io.open(cli, "wb")); cf:write("stub"); cf:close()
  local cfgp = dir .. "/config.json"
  local cred = dir .. "/r2_credentials.json"
  local cr = assert(io.open(cred, "wb"))
  cr:write('{"account_id":"a","access_key_id":"k","secret_access_key":"s","bucket":"b"}')
  cr:close()
  local cfg = assert(io.open(cfgp, "wb"))
  cfg:write(json.encode({ provider = "r2", token_paths = { r2 = cred } }))
  cfg:close()

  local command
  local r2 = json.decode(cs.remote_appids(cfgp, 77, {
    cli_path = cli,
    exec = function(cmd)
      command = cmd
      return '{"success":true,"app_ids":["250900","311690"]}\n[INFO] Shutdown complete', true
    end,
  }))
  eq(r2.success, true, "R2 remote listing succeeds through the official CLI")
  eq(r2.appids[1], 250900, "R2 app ids are normalized to numbers")
  ok(command:find("list%-remote%-app%-ids") ~= nil and command:find("r2", 1, true) ~= nil,
    "R2 listing invokes the provider-aware CLI command")

  local failed = json.decode(cs.remote_appids(cfgp, 77, {
    cli_path = cli,
    exec = function() return '{"success":false,"error":"offline"}', false end,
  }))
  eq(failed.success, false, "R2 listing failure remains an error")
  eq(failed.error, "offline", "R2 listing exposes the provider error")

  local probe_ok = cs.probe_provider(cfgp, "r2", {
    cli_path = cli,
    exec = function()
      return '[INFO] starting\n{"success":true,"app_ids":[]}\n[INFO] Shutdown complete', true
    end,
  })
  eq(probe_ok, true, "provider probe ignores log lines after the JSON response")

  local folder = dir .. "/folder"
  assert(os.execute("mkdir -p '" .. folder .. "/77/42' '" .. folder .. "/77/99'"))
  local ff = assert(io.open(cfgp, "wb"))
  ff:write(json.encode({ provider = "folder", sync_folder_path = folder }))
  ff:close()
  local listed = json.decode(cs.remote_appids(cfgp, 77))
  eq(listed.success, true, "custom folder listing succeeds")
  eq(listed.appids[1], 42, "custom folder first app found")
  eq(listed.appids[2], 99, "custom folder second app found")

  os.execute("rm -rf '" .. dir .. "'")
end

-- ── Cabinet: pairing-code and server validation (pure) ─────────────────────
do
  eq(cs.normalize_cabinet_code("ABCD-EFGH-JKMN"), "ABCD-EFGH-JKMN", "canonical code")
  eq(cs.normalize_cabinet_code(" abcd efgh jkmn "), "ABCD-EFGH-JKMN",
    "codes are case-insensitive and ignore spaces")
  eq(cs.normalize_cabinet_code("abcdefghjkmn"), "ABCD-EFGH-JKMN", "dashes are optional")
  eq(cs.normalize_cabinet_code("O0IL-1234-5678"), "0011-1234-5678",
    "O reads as 0, I and L as 1")
  eq(cs.normalize_cabinet_code("ABCD-EFGH-JKM"), nil, "an 11-character code is rejected")
  eq(cs.normalize_cabinet_code("ABCD-EFGH-JKMNP"), nil, "a 13-character code is rejected")
  eq(cs.normalize_cabinet_code("ABCD-EFGH-JKMU"), nil, "U is not Crockford base32")
  eq(cs.normalize_cabinet_code("ABCD-EFGH-JK;N"), nil, "punctuation is rejected")
  eq(cs.normalize_cabinet_code(nil), nil, "a missing code is rejected")

  eq(cs.parse_cabinet_server(nil).server, "https://cabinet.mc2.onl", "default server")
  eq(cs.parse_cabinet_server("  ").server, "https://cabinet.mc2.onl", "blank means default")
  eq(cs.parse_cabinet_server("Cabinet.Example.org/").server, "https://cabinet.example.org",
    "a bare host gets https and loses the trailing slash")
  eq(cs.parse_cabinet_server("https://cab.example:8443").server, "https://cab.example:8443",
    "an origin with a port is kept")
  local link = "https://cab.example/connect#cab_" .. string.rep("A", 43)
  eq(cs.parse_cabinet_server(link).link, link, "a full connect link is recognized")
  eq(cs.parse_cabinet_server("https://cab.example/some/path"), nil, "paths are rejected")
  eq(cs.parse_cabinet_server("https://cab.example'; rm -rf ~"), nil, "garbage is rejected")
  eq(cs.parse_cabinet_server("ftp://cab.example"), nil, "only http(s) origins")
end

-- ── Cabinet: connect stages the CLI's token; apply promotes it ─────────────
do
  local dir = os.tmpname(); os.remove(dir); assert(os.execute("mkdir -p '" .. dir .. "'"))
  local cli = dir .. "/cloud_redirect_cli"
  local cf = assert(io.open(cli, "wb")); cf:write("stub"); cf:close()
  local cfgp = dir .. "/config.json"
  local original = '{"provider":"gdrive","keep":5}'
  local f = assert(io.open(cfgp, "wb")); f:write(original); f:close()
  local cred = dir .. "/tokens_cabinet.json"
  local TOKEN = "cab_" .. string.rep("t", 43)

  -- Mimics cloud_redirect_cli cabinet-connect: writes both files, prints JSON.
  local commands = {}
  local function fake_cli(cmd)
    commands[#commands + 1] = cmd
    local w = assert(io.open(cred, "wb"))
    w:write(json.encode({ server = "https://cabinet.mc2.onl", token = TOKEN })); w:close()
    local c = assert(io.open(cfgp, "wb"))
    c:write(json.encode({ provider = "cabinet", token_path = cred,
                          token_paths = { cabinet = cred }, keep = 5 })); c:close()
    return '[INFO] pairing\n' .. json.encode({
      success = true, provider = "cabinet", server = "https://cabinet.mc2.onl",
      user = { id = "u1", name = "Mihai" }, credentials_path = cred, config_path = cfgp,
    }), true
  end

  local bad = json.decode(cs.cabinet_connect(cfgp, { code = "ABCD-EFGH-JKM" },
    { cli_path = cli, exec = function() error("CLI must not run for a malformed code") end }))
  eq(bad.success, false, "a malformed code fails locally")
  eq(bad.reason, "invalid_code", "a malformed code reports invalid_code")

  local res = json.decode(cs.cabinet_connect(cfgp, { code = "abcd efgh jkmn" },
    { cli_path = cli, exec = fake_cli }))
  eq(res.success, true, "cabinet connect succeeds")
  eq(res.pending, true, "cabinet connect is staged, not applied")
  eq(res.account.host, "cabinet.mc2.onl", "connect reports the server host")
  eq(res.account.user.name, "Mihai", "connect reports the Cabinet user")
  eq(res.account.token, nil, "connect never returns the token")
  ok(commands[1]:find("cabinet%-connect 'ABCD%-EFGH%-JKMN'") ~= nil,
    "the CLI receives the normalized code as one quoted argument")
  ok(not commands[1]:find("--server", 1, true), "the default server is implied")
  eq(assert(io.open(cfgp, "rb")):read("*a"), original,
    "connect leaves config.json as it was until Save and restart")
  ok(io.open(cred, "rb") == nil, "connect leaves no live credential before apply")

  local st = json.decode(cs.status(cfgp))
  eq(st.providers.cabinet.authenticated, false, "staged cabinet is not yet stored")
  eq(st.providers.cabinet.pending, true, "status reports the staged cabinet login")
  eq(st.providers.cabinet.pending_account.user.name, "Mihai",
    "status carries the staged account for display")

  local applied = json.decode(cs.apply_and_restart(cfgp,
    { provider = "cabinet", sync_activity = false }, { restart = function() return true end }))
  eq(applied.success, true, "cabinet draft applies")
  local cfg = cs.read_config(cfgp)
  eq(cfg.provider, "cabinet", "cabinet becomes the active provider")
  eq(cfg.token_paths.cabinet, cred, "cabinet credential path registered")
  eq(cfg.keep, 5, "unrelated config survives the cabinet apply")
  local stored = json.decode(assert(io.open(cred, "rb")):read("*a"))
  eq(stored.token, TOKEN, "the staged token is promoted")
  eq(stored.server, "https://cabinet.mc2.onl", "the server is promoted")
  st = json.decode(cs.status(cfgp))
  eq(st.authenticated, true, "provider_status: cabinet with server+token is authenticated")
  eq(st.providers.cabinet.settings.host, "cabinet.mc2.onl", "status exposes the host")
  eq(st.providers.cabinet.settings.token, nil, "status never exposes the token")
  eq(st.providers.cabinet.pending_account, nil, "apply clears the staged account")

  -- A custom server and a full connect link reach the CLI as separate args.
  commands = {}
  cs.cabinet_connect(cfgp, { code = "ABCDEFGHJKMN", server = "cab.example.org" },
    { cli_path = cli, exec = fake_cli })
  ok(commands[1]:find("'ABCD%-EFGH%-JKMN' '%-%-server' 'https://cab.example.org'") ~= nil,
    "a custom server is passed with --server")
  local link = "https://cab.example.org/connect#cab_" .. string.rep("B", 43)
  cs.cabinet_connect(cfgp, { code = "", server = link }, { cli_path = cli, exec = fake_cli })
  ok(commands[2]:find("cabinet%-connect '" .. link:gsub("%p", "%%%0") .. "'") ~= nil,
    "a connect link is used without a code")
  local still = json.decode(assert(io.open(cred, "rb")):read("*a"))
  eq(still.token, TOKEN, "a later staged connect leaves the applied token in place")
  json.decode(cs.discard_pending())
  eq(json.decode(cs.status(cfgp)).providers.cabinet.pending, false, "discard drops the staged login")

  -- Server-side rejection: the reason is classified, nothing is written.
  local before = assert(io.open(cfgp, "rb")):read("*a")
  local rejected = json.decode(cs.cabinet_connect(cfgp, { code = "ABCD-EFGH-JKMN" }, {
    cli_path = cli,
    exec = function() return '{"success":false,"error":"Cabinet pairing failed: invalid_code"}', false end,
  }))
  eq(rejected.success, false, "a rejected code fails")
  eq(rejected.reason, "code_rejected", "a rejected code is classified")
  eq(assert(io.open(cfgp, "rb")):read("*a"), before, "a rejected code changes nothing")

  -- GET /api/me for the stored token: name, revoked, unreachable.
  local seen
  local function fake_http(status, body)
    return { get = function(url, opts) seen = { url = url, opts = opts }
      return { status = status, body = body } end }
  end
  local acct = json.decode(cs.cabinet_account(cfgp,
    { http = fake_http(200, '{"user":{"id":"u1","name":"Mihai"}}') }))
  eq(acct.success, true, "account lookup succeeds")
  eq(acct.user.name, "Mihai", "account lookup returns the Cabinet user")
  eq(acct.host, "cabinet.mc2.onl", "account lookup returns the host")
  eq(seen.url, "https://cabinet.mc2.onl/api/me", "account lookup asks /api/me")
  local headers = seen.opts.headers
  eq(headers["Authorization"], "Bearer " .. TOKEN, "account lookup sends the bearer token")
  ok(type(headers["User-Agent"]) == "string" and headers["User-Agent"] ~= "",
    "account lookup sends a User-Agent (Cloudflare 1010)")
  eq(acct.token, nil, "account lookup never returns the token")
  local revoked = json.decode(cs.cabinet_account(cfgp,
    { http = fake_http(401, '{"error":"unauthorized"}') }))
  eq(revoked.reason, "revoked", "a 401 reads as a revoked device")
  local offline = json.decode(cs.cabinet_account(cfgp,
    { http = { get = function() return nil, "timeout" end } }))
  eq(offline.reason, "unreachable", "a transport failure reads as unreachable")

  -- Remote listing goes through the provider-generic CLI command.
  local listed_cmd
  local remote = json.decode(cs.remote_appids(cfgp, 77, { cli_path = cli,
    exec = function(cmd) listed_cmd = cmd; return '{"success":true,"app_ids":["42"]}', true end }))
  eq(remote.appids[1], 42, "cabinet remote listing works")
  ok(listed_cmd:find("list%-remote%-app%-ids 'cabinet'") ~= nil, "cabinet listing uses the CLI")

  -- Disconnect: the draft signs out to local and removes the credential.
  local out = json.decode(cs.apply_and_restart(cfgp,
    { provider = "local", sync_activity = false, sign_out_provider = "cabinet" },
    { restart = function() return true end }))
  eq(out.success, true, "cabinet disconnect applies")
  eq(cs.read_config(cfgp).provider, "local", "disconnect returns to local")
  ok(io.open(cred, "rb") == nil, "disconnect removes the cabinet credential")
  eq(json.decode(cs.cabinet_account(cfgp)).reason, "not_connected",
    "account lookup after disconnect is not_connected")
  local refused = json.decode(cs.apply_and_restart(cfgp,
    { provider = "cabinet", sync_activity = false }, { restart = function() return true end }))
  eq(refused.success, false, "cabinet cannot be applied without a credential")

  os.execute("rm -rf '" .. dir .. "'")
end

-- ── Cabinet RPCs are registered for the tab ────────────────────────────────
do
  local registry = cs.register({}, "/nonexistent/config.json")
  eq(type(registry.LumenCloudCabinetConnect), "function", "LumenCloudCabinetConnect registered")
  eq(type(registry.LumenCloudCabinetAccount), "function", "LumenCloudCabinetAccount registered")
  local rpc = require("rpc")
  local _, raw = rpc.dispatch(registry.LumenCloudCabinetConnect,
    { json = json.encode({ code = "nope" }) })
  eq(json.decode(raw).reason, "invalid_code", "connect RPC decodes its json argument")
end

print("test_cloudsettings: ALL PASS")
