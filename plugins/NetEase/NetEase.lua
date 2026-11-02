--[[
NetEase Cloud Music for Compás.

Search tracks, albums and artists, and browse your own playlists and liked
songs. Tracks stream through API 17 on-demand link resolution, queueing up to
500 at a time.

Sign-in is imported: a companion app (MusicDownloader for Android) writes the
account cookie to <SD card>/NetEase/session.txt over the remote-import
connection. The plugin moves it into its secrets and deletes the file.

Requests use NetEase's eapi transport (AES-128-ECB + MD5), implemented here in
plain Lua because the sandbox has no cipher API. Copy NetEase.lua to
<SD card>/.plugins/ and restart.
]]

plugin.define({
    id = "community.netease",
    name = "NetEase Cloud Music",
    version = "0.1.2",
    api_min = 17,
})

if not plugin.has_capability("playback.remote") or not plugin.has_capability("playback.remote_resolve") then
    plugin.show_toast("播放器版本过旧，无法播放网易云")
    return
end

local PROVIDER = "netease"
local EAPI = "https://interface.music.163.com/eapi"
local COOKIE_BASE = "os=android; appver=8.10.90"
local USER_AGENT = "Mozilla/5.0 (Linux; Android 14; Mobile) AppleWebKit/537.36 Chrome/120.0.0.0 Mobile Safari/537.36"
local SESSION_DIR = "NetEase"
local SESSION_FILE = "session.txt"
local PAGE = 30
-- json_decode caps a reply at 10000 entries; a song detail is ~150, a user playlist ~80.
local DETAIL_BATCH = 40
local PLAYLIST_PAGE = 50
-- Concurrent song-detail requests while a playlist fills in (http_request allows 4).
local DETAIL_PARALLEL = 2
local SEARCH_CAP = 90
local BROWSE_CAP = 475
local REMOTE_QUEUE_CAP = 500
local JSON_LIMIT = 524288
local QUALITIES = {
    { id = "standard", label = "标准 MP3 128k" },
    { id = "higher", label = "较高 MP3 192k" },
    { id = "exhigh", label = "极高 MP3 320k" },
    { id = "lossless", label = "无损 FLAC" },
    { id = "hires", label = "Hi-Res FLAC" },
}
local DEFAULT_QUALITY = "exhigh"

local session_generation = 0
local browse_generation = 0
local playback_generation = 0

---------------------------------------------------------------------------
-- AES-128-ECB encrypt with PKCS#7 padding (eapi only ever encrypts).
---------------------------------------------------------------------------

local SBOX = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
}

local function xtime(b)
    b = b << 1
    if b > 0xff then b = (b ~ 0x1b) & 0xff end
    return b
end

local function expand_key(key)
    local w = {}
    for i = 1, 16 do w[i] = key:byte(i) end
    local rcon = 1
    for i = 17, 176, 4 do
        local t1, t2, t3, t4 = w[i - 4], w[i - 3], w[i - 2], w[i - 1]
        if (i - 1) % 16 == 0 then
            t1, t2, t3, t4 = SBOX[t2 + 1] ~ rcon, SBOX[t3 + 1], SBOX[t4 + 1], SBOX[t1 + 1]
            rcon = xtime(rcon)
        end
        w[i] = w[i - 16] ~ t1
        w[i + 1] = w[i - 15] ~ t2
        w[i + 2] = w[i - 14] ~ t3
        w[i + 3] = w[i - 13] ~ t4
    end
    return w
end

local function encrypt_block(s, w)
    for i = 1, 16 do s[i] = s[i] ~ w[i] end
    for round = 1, 10 do
        for i = 1, 16 do s[i] = SBOX[s[i] + 1] end
        -- ShiftRows on column-major state (index = col * 4 + row + 1).
        s[2], s[6], s[10], s[14] = s[6], s[10], s[14], s[2]
        s[3], s[7], s[11], s[15] = s[11], s[15], s[3], s[7]
        s[4], s[8], s[12], s[16] = s[16], s[4], s[8], s[12]
        if round < 10 then
            for c = 0, 12, 4 do
                local a0, a1, a2, a3 = s[c + 1], s[c + 2], s[c + 3], s[c + 4]
                local all = a0 ~ a1 ~ a2 ~ a3
                s[c + 1] = a0 ~ all ~ xtime(a0 ~ a1)
                s[c + 2] = a1 ~ all ~ xtime(a1 ~ a2)
                s[c + 3] = a2 ~ all ~ xtime(a2 ~ a3)
                s[c + 4] = a3 ~ all ~ xtime(a3 ~ a0)
            end
        end
        local base = round * 16
        for i = 1, 16 do s[i] = s[i] ~ w[base + i] end
    end
end

local EAPI_KEY = expand_key("e82ckenh8dichen8")

local function aes_ecb_hex(text)
    local pad = 16 - (#text % 16)
    text = text .. string.rep(string.char(pad), pad)
    local out = {}
    local state = {}
    for offset = 1, #text, 16 do
        for i = 1, 16 do state[i] = text:byte(offset + i - 1) end
        encrypt_block(state, EAPI_KEY)
        for i = 1, 16 do out[#out + 1] = string.format("%02X", state[i]) end
    end
    return table.concat(out)
end

local function json_string(value)
    return '"' .. tostring(value):gsub('[%c"\\]', function(c)
        if c == '"' then return '\\"' end
        if c == "\\" then return "\\\\" end
        return string.format("\\u%04x", c:byte())
    end) .. '"'
end

-- Every field is sent as a JSON string; NetEase accepts that for numbers too,
-- and it avoids float formatting of ids.
local function fields_json(fields)
    local keys = {}
    for k in pairs(fields) do keys[#keys + 1] = k end
    table.sort(keys)
    local parts = {}
    for _, k in ipairs(keys) do parts[#parts + 1] = json_string(k) .. ":" .. json_string(fields[k]) end
    return "{" .. table.concat(parts, ",") .. "}"
end

local function eapi_params(api, fields)
    local json = fields_json(fields)
    local digest = plugin.md5("nobody" .. api .. "use" .. json .. "md5forencrypt")
    return aes_ecb_hex(api .. "-36cd479b6b5-" .. json .. "-36cd479b6b5-" .. digest)
end

---------------------------------------------------------------------------
-- Helpers
---------------------------------------------------------------------------

local function toast(message)
    plugin.show_toast(tostring(message or "请求失败"))
end

local function stored(key)
    local value = plugin.storage.get(key)
    if value == nil or value == "" then return nil end
    return value
end

local function id_string(value)
    if type(value) == "number" then
        local whole = math.tointeger(value)
        if whole then return tostring(whole) end
        return string.format("%.0f", value)
    end
    return tostring(value or "")
end

local function clip_utf8(text, limit)
    text = tostring(text or "")
    if #text <= limit then return text end
    local cut = limit - 3
    while cut > 0 do
        local next_byte = text:byte(cut + 1)
        if not next_byte or next_byte < 128 or next_byte >= 192 then break end
        cut = cut - 1
    end
    return text:sub(1, cut) .. "..."
end

local function trim(text)
    return (tostring(text or ""):gsub("^%s+", ""):gsub("%s+$", ""))
end

local function quality()
    local saved = stored("quality")
    for _, item in ipairs(QUALITIES) do
        if item.id == saved then return saved end
    end
    return DEFAULT_QUALITY
end

local function quality_index()
    local current = quality()
    for i, item in ipairs(QUALITIES) do
        if item.id == current then return i end
    end
    return 1
end

local function encode_type(level)
    if level == "lossless" or level == "hires" then return "flac" end
    return "mp3"
end

local function music_u()
    local value = plugin.secrets.get("music_u")
    if value == nil or value == "" then return nil end
    return value
end

local function signed_in()
    return music_u() ~= nil
end

local function cookie_header()
    local u = music_u()
    if not u then return COOKIE_BASE end
    return COOKIE_BASE .. "; MUSIC_U=" .. u
end

local function cover_url(pic)
    pic = tostring(pic or "")
    if pic == "" then return "" end
    if pic:find("param=", 1, true) then return pic end
    return pic .. (pic:find("?", 1, true) and "&" or "?") .. "param=320y320"
end

local function artists_name(list)
    if type(list) ~= "table" then return "" end
    local names = {}
    for _, artist in ipairs(list) do
        if type(artist) == "table" and artist.name and artist.name ~= "" then names[#names + 1] = artist.name end
    end
    return table.concat(names, " / ")
end

---------------------------------------------------------------------------
-- Transport
---------------------------------------------------------------------------

-- raw = true hands the undecoded body to callback (for replies too large to decode).
local function eapi(api, fields, callback, raw)
    local generation = session_generation
    local handle, start_err = plugin.http_request({
        url = EAPI .. api:gsub("^/api", ""),
        method = "POST",
        headers = {
            ["User-Agent"] = USER_AGENT,
            Cookie = cookie_header(),
        },
        body = "params=" .. eapi_params(api, fields),
        content_type = "application/x-www-form-urlencoded",
        connect_timeout_ms = 10000,
        total_timeout_ms = 20000,
        max_response_bytes = 2097152,
    }, function(status, body, err)
        if generation ~= session_generation then return end
        if err then callback(nil, err) return end
        if status ~= 200 then callback(nil, "HTTP " .. tostring(status)) return end
        if raw then callback(body or "") return end
        local data, decode_err = plugin.json_decode(body or "", { max_input_bytes = JSON_LIMIT })
        if type(data) ~= "table" then callback(nil, decode_err or "unreadable reply") return end
        local code = tonumber(data.code)
        if code and code ~= 200 then
            callback(nil, data.message or data.msg or ("code " .. id_string(code)), code)
            return
        end
        callback(data)
    end)
    if not handle then callback(nil, start_err or "request unavailable") end
end

---------------------------------------------------------------------------
-- Session import
---------------------------------------------------------------------------

local function clear_session()
    session_generation = session_generation + 1
    browse_generation = browse_generation + 1
    plugin.secrets.delete("music_u")
    plugin.storage.delete("user_id")
    plugin.storage.delete("nickname")
end

local function parse_music_u(text)
    text = trim(text)
    local value = text:match("MUSIC_U=([^;%s]+)")
    if value then return value end
    if text ~= "" and not text:find("[;=%s]") then return text end
    return nil
end

local function fetch_account(callback)
    eapi("/api/nuser/account/get", {}, function(data, err)
        local profile = data and data.profile
        if type(profile) ~= "table" or profile.userId == nil then
            callback(false, err or "未登录")
            return
        end
        plugin.storage.set("user_id", id_string(profile.userId))
        plugin.storage.set("nickname", tostring(profile.nickname or ""))
        callback(true)
    end)
end

-- Returns true when a pending session file was consumed.
local function import_session_file()
    local path = plugin.sd_root() .. "/" .. SESSION_DIR .. "/" .. SESSION_FILE
    local file = io.open(path, "rb")
    if not file then return false end
    local text = file:read("a") or ""
    file:close()
    os.remove(path)
    local value = parse_music_u(text)
    if not value then
        toast("登录信息无效")
        return true
    end
    clear_session()
    plugin.secrets.set("music_u", value)
    return true
end

---------------------------------------------------------------------------
-- Models
---------------------------------------------------------------------------

local function track_from(obj, album_hint)
    if type(obj) ~= "table" or obj.id == nil then return nil end
    local hint = album_hint or {}
    local album = type(obj.al) == "table" and obj.al or (type(obj.album) == "table" and obj.album or {})
    local artist = artists_name(obj.ar or obj.artists)
    local title = obj.name or "未知曲目"
    if artist == "" then artist = hint.artist or "未知歌手" end
    return {
        id = id_string(obj.id),
        title = title,
        artist = artist,
        album = album.name or hint.title or "",
        cover = cover_url(album.picUrl) ~= "" and cover_url(album.picUrl) or (hint.cover or ""),
        duration_ms = tonumber(obj.dt or obj.duration) or 0,
        label = title .. " - " .. artist,
    }
end

local function tracks_from(list, album_hint)
    local rows = {}
    if type(list) ~= "table" then return rows end
    for _, obj in ipairs(list) do
        local track = track_from(obj, album_hint)
        if track then rows[#rows + 1] = track end
    end
    return rows
end

local function album_from(obj)
    if type(obj) ~= "table" or obj.id == nil then return nil end
    local artist = artists_name(obj.artists)
    if artist == "" and type(obj.artist) == "table" then artist = obj.artist.name or "" end
    local title = obj.name or "未知专辑"
    return {
        id = id_string(obj.id),
        title = title,
        artist = artist,
        cover = cover_url(obj.picUrl),
        label = title .. (artist ~= "" and (" - " .. artist) or ""),
    }
end

---------------------------------------------------------------------------
-- Playback
---------------------------------------------------------------------------

local function stream_reason(code, item)
    if type(item) == "table" and (item.freeTrialInfo ~= nil or tonumber(item.fee) == 1 or tonumber(item.fee) == 4) then
        return "subscription"
    end
    if code == 301 or code == -462 then return "auth" end
    return "unavailable"
end

local function resolve_stream(track_id, level, callback)
    eapi("/api/song/enhance/player/url/v1", {
        ids = "[" .. track_id .. "]",
        level = level,
        encodeType = encode_type(level),
    }, function(data, err, code)
        if not data then callback(nil, err, code and stream_reason(code) or "network") return end
        local item = type(data.data) == "table" and data.data[1] or nil
        local url = type(item) == "table" and item.url or nil
        if type(url) ~= "string" or not url:match("^https?://") or item.freeTrialInfo ~= nil then
            callback(nil, "no stream link", stream_reason(tonumber(item and item.code), item))
            return
        end
        local codec = tostring(item.type or encode_type(level)):lower()
        if codec ~= "mp3" and codec ~= "flac" then
            if level ~= "exhigh" and level ~= "higher" and level ~= "standard" then
                resolve_stream(track_id, "exhigh", callback)
            else
                callback(nil, "unsupported format " .. codec, "quality")
            end
            return
        end
        local ttl = math.floor((tonumber(item.expi) or 1200) - 60)
        if ttl < 30 then ttl = 30 end
        if ttl > 86400 then ttl = 86400 end
        callback({
            stream_url = url,
            codec = codec,
            bitrate_kbps = math.floor((tonumber(item.br) or 0) / 1000),
            url_ttl_s = ttl,
        })
    end)
end

plugin.on("remote_stream_needed", function(provider, track_id, request_id)
    if provider ~= PROVIDER then return end
    local generation = playback_generation
    resolve_stream(tostring(track_id), quality(), function(link, err, reason)
        if generation ~= playback_generation then
            plugin.provide_remote_stream(request_id, { error = "Playback request was replaced" })
            return
        end
        if not link then
            plugin.provide_remote_stream(request_id, { error = tostring(err or "no stream link"), reason = reason })
            return
        end
        plugin.provide_remote_stream(request_id, link)
    end)
end)

local function play_tracks(tracks, start_index)
    playback_generation = playback_generation + 1
    local start = start_index or 1
    local ordered = {}
    for i = start, #tracks do
        if #ordered >= REMOTE_QUEUE_CAP then break end
        ordered[#ordered + 1] = tracks[i]
    end
    for i = 1, start - 1 do
        if #ordered >= REMOTE_QUEUE_CAP then break end
        ordered[#ordered + 1] = tracks[i]
    end
    if #ordered == 0 then toast("没有可播放的曲目") return end
    local queue = {}
    for i, track in ipairs(ordered) do
        queue[i] = {
            provider = PROVIDER,
            track_id = track.id,
            title = clip_utf8(track.title, 127),
            artist = clip_utf8(track.artist, 127),
            album = clip_utf8(track.album, 127),
            duration_ms = math.floor(track.duration_ms or 0),
            artwork_url = track.cover,
            codec = encode_type(quality()),
        }
    end
    plugin.queue_remote_list(queue, 1)
end

---------------------------------------------------------------------------
-- Browsing
---------------------------------------------------------------------------

local show_list

show_list = function(title, labels, on_select, options)
    local handle
    handle = plugin.show_list(title, labels, function(index)
        on_select(index, handle)
    end, options)
    return handle
end

local function parent_showing(parent)
    return parent == nil or plugin.is_list_showing(parent)
end

local function show_retry(parent, retry)
    if not parent_showing(parent) then return end
    local handle
    handle = plugin.show_list("加载失败", { "重试" }, function(index)
        if index == 1 then retry(handle) end
    end)
end

local function show_rows(title, rows, on_pick)
    local labels = {}
    for i, row in ipairs(rows) do labels[i] = clip_utf8(row.label, 140) end
    return show_list(title, labels, function(index, handle)
        if rows[index] then on_pick(rows[index], handle, index) end
    end)
end

local function show_tracks(title, tracks)
    if #tracks == 0 then toast("没有曲目") return end
    local rows = { { label = "播放全部", play_all = true } }
    for i = 1, math.min(#tracks, BROWSE_CAP) do rows[#rows + 1] = tracks[i] end
    show_rows(title, rows, function(row, _, index)
        if row.play_all then play_tracks(tracks, 1) else play_tracks(tracks, index - 1) end
    end)
end

-- Opens the list after the first detail batch, then fetches the rest
-- DETAIL_PARALLEL at a time and replaces the list in place (scroll kept).
-- Rows only ever grow as a contiguous prefix of ids, so indices stay valid.
local function show_tracks_progressive(title, ids, parent, on_first_error)
    local generation = browse_generation
    local by_id, done, attempts = {}, {}, {}
    local batch_count = math.ceil(#ids / DETAIL_BATCH)
    local next_batch, in_flight, contiguous = 1, 0, 0
    local tracks, handle, stopped = {}, nil, false

    local function render()
        local upto = math.min(#ids, contiguous * DETAIL_BATCH)
        tracks = {}
        for i = 1, upto do
            if by_id[ids[i]] then tracks[#tracks + 1] = by_id[ids[i]] end
        end
        local rows = { { label = "播放全部", play_all = true } }
        for i = 1, math.min(#tracks, BROWSE_CAP) do rows[#rows + 1] = tracks[i] end
        local labels = {}
        for i, row in ipairs(rows) do labels[i] = clip_utf8(row.label, 140) end
        local heading = upto < #ids and (title .. "  " .. upto .. "/" .. #ids) or title
        local on_select = function(index)
            local row = rows[index]
            if not row then return end
            if row.play_all then play_tracks(tracks, 1) else play_tracks(tracks, index - 1) end
        end
        if handle then
            if not plugin.is_list_showing(handle) then stopped = true return end
            handle = show_list(heading, labels, on_select, { replace = handle })
            if not handle then stopped = true end
        else
            if not parent_showing(parent) then stopped = true return end
            handle = show_list(heading, labels, on_select)
        end
    end

    local pump
    local function fetch(batch)
        in_flight = in_flight + 1
        attempts[batch] = (attempts[batch] or 0) + 1
        local from = (batch - 1) * DETAIL_BATCH + 1
        local parts = {}
        for i = from, math.min(#ids, from + DETAIL_BATCH - 1) do parts[#parts + 1] = '{"id":' .. ids[i] .. '}' end
        eapi("/api/v3/song/detail", { c = "[" .. table.concat(parts, ",") .. "]" }, function(data, err)
            in_flight = in_flight - 1
            if generation ~= browse_generation or stopped then return end
            if not data then
                if batch == 1 and not handle then
                    stopped = true
                    on_first_error(err)
                elseif attempts[batch] < 3 then
                    fetch(batch)
                else
                    stopped = true
                    toast(err)
                end
                return
            end
            for _, track in ipairs(tracks_from(data.songs)) do by_id[track.id] = track end
            done[batch] = true
            local before = contiguous
            while done[contiguous + 1] do contiguous = contiguous + 1 end
            if contiguous ~= before then render() end
            if not stopped then pump() end
        end)
    end

    pump = function()
        local limit = handle and DETAIL_PARALLEL or 1
        while not stopped and in_flight < limit and next_batch <= batch_count do
            local batch = next_batch
            next_batch = next_batch + 1
            fetch(batch)
        end
    end
    pump()
end

local function open_playlist(playlist, parent)
    local generation = browse_generation
    local function load(active)
        eapi("/api/v6/playlist/detail", { id = playlist.id, n = "0", s = "0" }, function(body, err)
            if generation ~= browse_generation or not parent_showing(active or parent) then return end
            -- trackIds alone exceeds the json_decode entry cap past ~700 tracks, so scan it.
            local ids = {}
            local from = body and body:find('"trackIds":[', 1, true)
            if from then
                for id in body:gmatch('{"id":(%d+),"v":', from) do
                    ids[#ids + 1] = id
                    if #ids >= REMOTE_QUEUE_CAP then break end
                end
            end
            if #ids == 0 then
                if body and not err then
                    local data = plugin.json_decode(body, { max_input_bytes = JSON_LIMIT })
                    local code = type(data) == "table" and tonumber(data.code)
                    if code and code ~= 200 then err = data.message or data.msg or ("code " .. id_string(code)) end
                end
                if err then
                    toast(err)
                    show_retry(active or parent, load)
                else
                    toast("没有曲目")
                end
                return
            end
            show_tracks_progressive(playlist.name, ids, active or parent, function(detail_err)
                toast(detail_err)
                show_retry(active or parent, load)
            end)
        end, true)
    end
    load(nil)
end

local function open_album(album, parent)
    local generation = browse_generation
    local function load(active)
        eapi("/api/v1/album/" .. album.id, { id = album.id }, function(data, err)
            if generation ~= browse_generation or not parent_showing(active or parent) then return end
            if not data then
                toast(err)
                show_retry(active or parent, load)
                return
            end
            local info = album_from(data.album) or album
            show_tracks(info.title, tracks_from(data.songs, info))
        end)
    end
    load(nil)
end

local function open_artist(artist, parent)
    local generation = browse_generation
    local albums = {}
    local function page(offset, active)
        eapi("/api/artist/albums/" .. artist.id, { limit = tostring(PAGE), offset = tostring(offset), total = "true" },
            function(data, err)
                if generation ~= browse_generation or not parent_showing(active or parent) then return end
                if not data then
                    toast(err)
                    show_retry(active or parent, function(h) page(offset, h) end)
                    return
                end
                local list = type(data.hotAlbums) == "table" and data.hotAlbums or {}
                for _, obj in ipairs(list) do
                    local album = album_from(obj)
                    if album then albums[#albums + 1] = album end
                end
                if data.more and #list > 0 and #albums < BROWSE_CAP then
                    page(offset + #list, active)
                    return
                end
                if #albums == 0 then toast("没有专辑") return end
                show_rows(artist.name, albums, function(album, handle) open_album(album, handle) end)
            end)
    end
    page(0, nil)
end

local SEARCH_TYPES = { tracks = "1", albums = "10", artists = "100" }

local function search(kind, query, parent)
    local generation = browse_generation
    local found = {}
    local function page(offset, active)
        eapi("/api/cloudsearch/pc", {
            s = query, type = SEARCH_TYPES[kind], limit = tostring(PAGE), offset = tostring(offset), total = "true",
        }, function(data, err)
            if generation ~= browse_generation or not parent_showing(active or parent) then return end
            local result = data and data.result
            if type(result) ~= "table" then
                toast(err or "没有结果")
                if not data then show_retry(active or parent, function(h) page(offset, h) end) end
                return
            end
            local list = result.songs or result.albums or result.artists or {}
            for _, obj in ipairs(list) do found[#found + 1] = obj end
            local total = tonumber(result.songCount or result.albumCount or result.artistCount) or 0
            if #list == PAGE and #found < SEARCH_CAP and #found < total then
                page(offset + PAGE, active)
                return
            end
            if kind == "tracks" then
                show_tracks(query, tracks_from(found))
            elseif kind == "albums" then
                local rows = {}
                for _, obj in ipairs(found) do
                    local album = album_from(obj)
                    if album then rows[#rows + 1] = album end
                end
                if #rows == 0 then toast("没有结果") return end
                show_rows(query, rows, function(album, handle) open_album(album, handle) end)
            else
                local rows = {}
                for _, obj in ipairs(found) do
                    if type(obj) == "table" and obj.id ~= nil then
                        rows[#rows + 1] = { id = id_string(obj.id), name = obj.name or "", label = obj.name or "" }
                    end
                end
                if #rows == 0 then toast("没有结果") return end
                show_rows(query, rows, function(artist, handle) open_artist(artist, handle) end)
            end
        end)
    end
    page(0, nil)
end

local function ask_search(kind, title, parent)
    local ok, err = plugin.show_text_input(title, nil, false, function(query)
        query = trim(query)
        if query == "" then return end
        search(kind, query, parent)
    end)
    if ok == false then toast(err) end
end

-- done(playlists) with { id, name, special, label } or done(nil, err).
local function fetch_my_playlists(done)
    local uid = stored("user_id")
    if not uid then done(nil, "未登录") return end
    local generation = browse_generation
    local all = {}
    local function page(offset)
        eapi("/api/user/playlist", { uid = uid, limit = tostring(PLAYLIST_PAGE), offset = tostring(offset), includeVideo = "false" },
            function(data, err)
                if generation ~= browse_generation then return end
                if not data then done(nil, err) return end
                local list = type(data.playlist) == "table" and data.playlist or {}
                for _, obj in ipairs(list) do
                    if type(obj) == "table" and obj.id ~= nil then
                        local name = obj.name or "歌单"
                        local count = tonumber(obj.trackCount) or 0
                        all[#all + 1] = {
                            id = id_string(obj.id),
                            name = name,
                            special = tonumber(obj.specialType) == 5,
                            label = name .. "（" .. math.floor(count) .. "）",
                        }
                    end
                end
                if data.more and #list > 0 and #all < BROWSE_CAP then page(offset + #list) else done(all) end
            end)
    end
    page(0)
end

local function require_session(next_step)
    if not signed_in() then toast("未登录") return end
    if stored("user_id") then next_step() return end
    fetch_account(function(ok, err)
        if not ok then toast(err) return end
        next_step()
    end)
end

local function show_my_playlists(parent)
    require_session(function()
        fetch_my_playlists(function(list, err)
            if not parent_showing(parent) then return end
            if not list then toast(err) show_retry(parent, function(h) show_my_playlists(h) end) return end
            if #list == 0 then toast("没有歌单") return end
            show_rows("我的歌单", list, function(playlist, handle) open_playlist(playlist, handle) end)
        end)
    end)
end

local function show_liked(parent)
    require_session(function()
        fetch_my_playlists(function(list, err)
            if not parent_showing(parent) then return end
            if not list then toast(err) show_retry(parent, function(h) show_liked(h) end) return end
            local liked = nil
            for _, playlist in ipairs(list) do
                if playlist.special then liked = playlist break end
            end
            liked = liked or list[1]
            if not liked then toast("没有歌单") return end
            open_playlist(liked, parent)
        end)
    end)
end

local function choose_quality()
    local labels = {}
    for i, item in ipairs(QUALITIES) do labels[i] = item.label end
    show_list("音质", labels, function(index)
        plugin.storage.set("quality", QUALITIES[index].id)
    end, { selected = quality_index() })
end

local show_home

show_home = function()
    local items = { "搜索单曲", "搜索专辑", "搜索歌手", "我喜欢的音乐", "我的歌单", "音质" }
    if signed_in() then items[#items + 1] = "退出登录" end
    show_list("网易云音乐", items, function(index, handle)
        if index == 1 then ask_search("tracks", "搜索单曲", handle)
        elseif index == 2 then ask_search("albums", "搜索专辑", handle)
        elseif index == 3 then ask_search("artists", "搜索歌手", handle)
        elseif index == 4 then show_liked(handle)
        elseif index == 5 then show_my_playlists(handle)
        elseif index == 6 then choose_quality()
        elseif index == 7 then
            playback_generation = playback_generation + 1
            clear_session()
        end
    end)
end

local function open_netease()
    if import_session_file() and signed_in() then
        fetch_account(function(ok, err)
            if not ok then
                clear_session()
                toast(err)
            end
        end)
    end
    show_home()
end

plugin.register_stream_media_tile("网易云音乐", open_netease)
