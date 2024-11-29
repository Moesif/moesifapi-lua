-- logger.lua
local Logger = {}

-- Log levels
Logger.INFO = 1
Logger.ERROR = 2
Logger.DEBUG = 3

-- Default log level
Logger.current_level = Logger.INFO

-- Function to get the current timestamp
local function get_timestamp()
  return os.date("%Y-%m-%d %H:%M:%S")
end

-- Internal function to log messages with levels
local function log(level, level_name, msg)
  if level >= Logger.current_level then
    local timestamp = get_timestamp()
    print(string.format("[%s] [%s] %s", timestamp, level_name, msg))
  end
end

-- Public methods for different log levels
function Logger.info(msg)
  log(Logger.INFO, "INFO", msg)
end

function Logger.error(msg)
  log(Logger.ERROR, "ERROR", msg)
end

function Logger.debug(msg)
  log(Logger.DEBUG, "DEBUG", msg)
end

-- Set the current log level
function Logger.set_level(level)
  Logger.current_level = level
end

return Logger
