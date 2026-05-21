# frozen_string_literal: true

def debug_output(msg)
  $stderr.puts("[DEBUG] #{msg}") if ENV["VIVARIUM_DEBUG"]
end

debug_output "=== sudo attempt demo ==="

debug_output "[1] Attempting: sudo id"
system("sudo", "-n", "id")

debug_output "[2] Attempting: sudo cat /etc/shadow"
system("sudo", "-n", "cat", "/etc/shadow")

debug_output "[3] Attempting: sudo cat /proc/1/environ"
system("sudo", "-n", "cat", "/proc/1/environ")

debug_output "=== done ==="
