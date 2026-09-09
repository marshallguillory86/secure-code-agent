require 'digest'
require 'yaml'

def command_injection(user_input)
  system("ls #{user_input}")
end

# Plain `eval` belongs to RuboCop's Security/Eval, which is in the floor (D12).
# What is left to us is the receiver-context pair RuboCop does not cover.
def code_injection(payload)
  instance_eval(payload)
end

def unsafe_deserialization(blob)
  Marshal.load(blob)
  YAML.load(blob)
end

def weak_hash(data)
  Digest::MD5.hexdigest(data)
end
