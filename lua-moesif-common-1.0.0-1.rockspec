package = "lua-moesif-common"  -- TODO: rename, must match the info in the filename of this rockspec!
                                  -- as a convention; stick to the prefix: `kong-plugin-`
version = "1.0.0-1"               -- TODO: renumber, must match the info in the filename of this rockspec!
-- The version '1.0.0' is the source code version, the trailing '1' is the version of this rockspec.
-- whenever the source version changes, the rockspec should be reset to 1. The rockspec version is only
-- updated (incremented) when this file changes, but the source remains the same.

-- TODO: This is the name to set in the Kong configuration `custom_plugins` setting.
-- Here we extract it from the package name.
local pluginName = package:match("^lua%-resty%-(.+)$")  -- "moesif"

supported_platforms = {"linux", "macosx"}
source = {
  url = "git://github.com/Moesif/lua-moesif-common/",
  tag = "1.0.0"
}

description = {
  summary = "Moesif Common library",
  homepage = "http://moesif.com",
  license = "MIT"
}

dependencies = {
  "lua-resty-http",
  "lua-zlib"
}

build = {
  type = "builtin",
  modules = {
    ["lua.moesif.common.moesif_client"] = "lua/moesif/common/moesif_client.lua",
    ["lua.moesif.common.logger"] = "lua/moesif/common/logger.lua",
    ["lua.moesif.common.prepare_payload"] = "lua/moesif/common/prepare_payload.lua",
    ["lua.moesif.common.http_connection"] = "lua/moesif/common/http_connection.lua",
    ["lua.moesif.common.client_ip"] = "lua/moesif/common/client_ip.lua",
    ["lua.moesif.common.base64"] = "lua/moesif/common/base64.lua",
    ["lua.moesif.common.app_config"] = "lua/moesif/common/app_config.lua",
  }
}
