require 'digest'
require 'yaml'

def command_injection(user_input)
  system("ls #{user_input}")
end

def code_injection(payload)
  eval(payload)
end

def unsafe_deserialization(blob)
  Marshal.load(blob)
  YAML.load(blob)
end

def weak_hash(data)
  Digest::MD5.hexdigest(data)
end
