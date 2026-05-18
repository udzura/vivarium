# frozen_string_literal: true

require "test_helper"

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
