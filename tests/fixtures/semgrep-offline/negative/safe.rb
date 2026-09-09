require 'digest'
require 'json'
require 'yaml'

def command_with_argv(user_input)
  system("ls", user_input)
end

def parse_data(payload)
  JSON.parse(payload)
end

def safe_deserialization(blob)
  YAML.safe_load(blob)
end

def strong_hash(data)
  Digest::SHA256.hexdigest(data)
end
