# frozen_string_literal: true

require "test_helper"
require "ostruct"
require "stringio"
require "json"

class VivariumTest < Test::Unit::TestCase
  test "VERSION" do
    assert do
      ::Vivarium.const_defined?(:VERSION)
    end
  end

  test "event can be parsed from binary payload" do
    binary = [123_456_789].pack("Q<") + [1234].pack("L<") +
             "path_open".ljust(16, "\x00") +
             "/tmp/a.txt".ljust(Vivarium::EVENT_PAYLOAD_SIZE, "\x00")
    binary = binary.ljust(Vivarium::EVENT_STRUCT_SIZE, "\x00")
    event = Vivarium::Event.from_binary(binary)

    assert_equal 123_456_789, event.ktime_ns
    assert_equal 1234, event.pid
    assert_equal "path_open", event.event_name.force_encoding("UTF-8")
    assert_equal "/tmp/a.txt", event.payload.force_encoding("UTF-8")
  end

  test "decode dns qname" do
    raw = "\x06google\x03com\x00".b.ljust(Vivarium::EVENT_PAYLOAD_SIZE, "\x00")
    assert_equal "google.com", Vivarium.decode_dns_qname(raw)
  end

  test "decode proc_exec payload" do
    payload = "/bin/sh".ljust(Vivarium::PROC_EXEC_SLOT_SIZE, "\x00") +
              "sh".ljust(Vivarium::PROC_EXEC_SLOT_SIZE, "\x00") +
              "-c".ljust(Vivarium::PROC_EXEC_SLOT_SIZE, "\x00") +
              "echo hello".ljust(Vivarium::PROC_EXEC_SLOT_SIZE, "\x00")
    decoded = Vivarium.decode_proc_exec_payload(payload)

    assert_match(%r{filename="/bin/sh"}, decoded)
    assert_match(%r{argv=\["sh", "-c", "echo hello"\]}, decoded)
  end

  test "decode ptrace_check payload" do
    payload = [0x42].pack("L<").ljust(Vivarium::EVENT_PAYLOAD_SIZE, "\x00")
    decoded = Vivarium.decode_ptrace_check_payload(payload)
    assert_match(/mode=0x42/, decoded)
  end

  test "decode sb_mount payload" do
    payload = [0x1234].pack("Q<") +
              "/dev/loop0".ljust(120, "\x00") +
              "ext4".ljust(120, "\x00")
    payload = payload.ljust(Vivarium::EVENT_PAYLOAD_SIZE, "\x00")
    decoded = Vivarium.decode_sb_mount_payload(payload)

    assert_match(/flags=0x1234/, decoded)
    assert_match(%r{dev_name="/dev/loop0"}, decoded)
    assert_match(%r{fs_type="ext4"}, decoded)
  end

  test "decode kernel_read_file payload" do
    payload = [3, 1].pack("L<L<").ljust(Vivarium::EVENT_PAYLOAD_SIZE, "\x00")
    decoded = Vivarium.decode_kernel_read_file_payload(payload)
    assert_match(/id=3/, decoded)
    assert_match(/contents=1/, decoded)
  end

  test "decode task_kill payload" do
    payload = [9].pack("l<").ljust(Vivarium::EVENT_PAYLOAD_SIZE, "\x00")
    decoded = Vivarium.decode_task_kill_payload(payload)
    assert_match(/sig=9/, decoded)
    assert_match(/signame=KILL/, decoded)
  end

  test "decode setid_change payload" do
    payload = [0x03].pack("L<").ljust(Vivarium::EVENT_PAYLOAD_SIZE, "\x00")
    decoded = Vivarium.decode_setid_change_payload(payload)
    assert_match(/flags=0x3/, decoded)
    assert_match(/LSM_SETID_ID/, decoded)
    assert_match(/LSM_SETID_RE/, decoded)
  end

  test "decode capable_check payload" do
    payload = [21, 0x10].pack("L<L<").ljust(Vivarium::EVENT_PAYLOAD_SIZE, "\x00")
    decoded = Vivarium.decode_capable_check_payload(payload)
    assert_match(/cap=21\(CAP_SYS_ADMIN\)/, decoded)
    assert_match(/opts=0x10/, decoded)
  end

  test "decode bprm_creds payload" do
    payload = [1].pack("C") + "/usr/bin/sudo".ljust(Vivarium::EVENT_PAYLOAD_SIZE - 1, "\x00")
    decoded = Vivarium.decode_bprm_creds_payload(payload)
    assert_match(/has_file=1/, decoded)
    assert_match(%r{file="/usr/bin/sudo"}, decoded)
  end

  test "event severity mapping" do
    assert_equal "high", Vivarium.event_severity("setid_change")
    assert_equal "high", Vivarium.event_severity("capable_check")
    assert_equal "high", Vivarium.event_severity("bprm_creds")
    assert_equal "high", Vivarium.event_severity("task_kill")
    assert_equal "high", Vivarium.event_severity("ptrace_check")
    assert_equal "high", Vivarium.event_severity("sb_mount")
    assert_equal "high", Vivarium.event_severity("kernel_read_file")
    assert_equal "medium", Vivarium.event_severity("proc_exec")
    assert_equal "medium", Vivarium.event_severity("file_chmod")
  end

  test "event has severity metadata" do
    event = Vivarium::Event.new(ktime_ns: 1, pid: 100, event_name: "task_kill", payload: "")
    assert_equal "high", event.severity
  end

  test "logger human colors high severity in red" do
    io = StringIO.new
    logger = Vivarium::Logger.new(dest: io, format: :human)
    tp = OpenStruct.new(defined_class: "Kernel", method_id: "system", event: "return", path: "demo.rb", lineno: 10)
    event = Vivarium::Event.new(ktime_ns: 10, pid: 200, event_name: "task_kill", payload: [15].pack("l<").ljust(Vivarium::EVENT_PAYLOAD_SIZE, "\x00"))

    logger.log([event], tp, [])
    out = io.string
    assert_match(/severity=high/, out)
    assert_match(/\e\[31m/, out)
  end

  test "logger json includes severity" do
    io = StringIO.new
    logger = Vivarium::Logger.new(dest: io, format: :json)
    tp = OpenStruct.new(defined_class: "Kernel", method_id: "system", event: "return", path: "demo.rb", lineno: 10)
    high_event = Vivarium::Event.new(ktime_ns: 1, pid: 1, event_name: "task_kill", payload: [9].pack("l<").ljust(Vivarium::EVENT_PAYLOAD_SIZE, "\x00"))
    medium_event = Vivarium::Event.new(ktime_ns: 2, pid: 2, event_name: "proc_exec", payload: "".ljust(Vivarium::EVENT_PAYLOAD_SIZE, "\x00"))

    logger.log([high_event, medium_event], tp, [])
    parsed = JSON.parse(io.string)
    assert_equal "high", parsed.fetch("events").first.fetch("severity")
    assert_equal "medium", parsed.fetch("events").last.fetch("severity")
  end

  test "decode file_symlink payload" do
    target = "/path/to/target"
    link_name = "mylink"
    payload = target.ljust(128, "\x00") + link_name.ljust(128, "\x00")
    decoded = Vivarium.decode_file_symlink_payload(payload)
    assert_match(/target=.*#{Regexp.escape(target)}/, decoded)
    assert_match(/link_name=.*#{Regexp.escape(link_name)}/, decoded)
  end

  test "decode file_hardlink payload" do
    old_path = "/path/to/file.txt"
    new_name = "hardlink"
    payload = old_path.ljust(128, "\x00") + new_name.ljust(128, "\x00")
    decoded = Vivarium.decode_file_hardlink_payload(payload)
    assert_match(/old_path=.*#{Regexp.escape(old_path)}/, decoded)
    assert_match(/new_name=.*#{Regexp.escape(new_name)}/, decoded)
  end

  test "decode file_rename payload" do
    old_name = "oldname.txt"
    new_name = "newname.txt"
    payload = old_name.ljust(128, "\x00") + new_name.ljust(128, "\x00")
    decoded = Vivarium.decode_file_rename_payload(payload)
    assert_match(/old_name=.*#{Regexp.escape(old_name)}/, decoded)
    assert_match(/new_name=.*#{Regexp.escape(new_name)}/, decoded)
  end

  test "decode file_chmod payload" do
    mode = 0o644
    path = "/etc/passwd"
    payload = [mode].pack("S<") + path.ljust(254, "\x00")
    decoded = Vivarium.decode_file_chmod_payload(payload)
    assert_match(/mode=0o644/, decoded)
    assert_match(/path=.*#{Regexp.escape(path)}/, decoded)
  end

  test "decode file_getdents payload" do
    fd = 3
    count = 4096
    payload = [fd, count].pack("L<L<") + "\x00" * (Vivarium::EVENT_PAYLOAD_SIZE - 8)
    decoded = Vivarium.decode_file_getdents_payload(payload)
    assert_match(/fd=3/, decoded)
    assert_match(/count=4096/, decoded)
  end

  test "render event payload for file_symlink" do
    target = "link_target"
    link_name = "symlink_name"
    payload = target.ljust(128, "\x00") + link_name.ljust(128, "\x00")
    event = Vivarium::Event.new(ktime_ns: 100, pid: 1234, event_name: "file_symlink", payload: payload)
    rendered = Vivarium.render_event_payload(event)
    assert_match(/target=/, rendered)
    assert_match(/link_name=/, rendered)
  end

  test "render event payload for proc_exec" do
    payload = "/usr/bin/env".ljust(Vivarium::PROC_EXEC_SLOT_SIZE, "\x00") +
              "env".ljust(Vivarium::PROC_EXEC_SLOT_SIZE, "\x00") +
              "ruby".ljust(Vivarium::PROC_EXEC_SLOT_SIZE, "\x00") +
              "script.rb".ljust(Vivarium::PROC_EXEC_SLOT_SIZE, "\x00")
    event = Vivarium::Event.new(ktime_ns: 100, pid: 1234, event_name: "proc_exec", payload: payload)
    rendered = Vivarium.render_event_payload(event)

    assert_match(%r{filename="/usr/bin/env"}, rendered)
    assert_match(%r{"ruby"}, rendered)
    assert_match(%r{"script.rb"}, rendered)
  end

  test "render event payload for ptrace_check" do
    payload = [0x2].pack("L<").ljust(Vivarium::EVENT_PAYLOAD_SIZE, "\x00")
    event = Vivarium::Event.new(ktime_ns: 100, pid: 1234, event_name: "ptrace_check", payload: payload)
    rendered = Vivarium.render_event_payload(event)
    assert_match(/mode=0x2/, rendered)
  end

  test "observe without block is supported" do
    err = assert_raise(Vivarium::Error) do
      Vivarium.observe(pin_dir: "/tmp/vivarium-not-found")
    end
    assert_match(/failed to open pinned maps/, err.message)
  end

  test "top_observe exists" do
    assert_respond_to Vivarium, :top_observe
  end

  test "map store raises readable error when pin is missing" do
    err = assert_raise(Vivarium::Error) do
      Vivarium::MapStore.new(pin_dir: "/tmp/vivarium-not-found")
    end
    assert_match(/failed to open pinned maps/, err.message)
  end
end
