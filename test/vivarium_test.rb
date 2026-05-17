# frozen_string_literal: true

require "test_helper"

class VivariumTest < Test::Unit::TestCase
  test "VERSION" do
    assert do
      ::Vivarium.const_defined?(:VERSION)
    end
  end

  test "event can be parsed from binary payload" do
    binary = [1234].pack("L<") + "path_open".ljust(16, "\x00") + "/tmp/a.txt".ljust(Vivarium::EVENT_PAYLOAD_SIZE, "\x00")
    event = Vivarium::Event.from_binary(binary)

    assert_equal 1234, event.pid
    assert_equal "path_open", event.event_name.force_encoding("UTF-8")
    assert_equal "/tmp/a.txt", event.payload.force_encoding("UTF-8")
  end

  test "decode dns qname" do
    raw = "\x06google\x03com\x00".b.ljust(Vivarium::EVENT_PAYLOAD_SIZE, "\x00")
    assert_equal "google.com", Vivarium.decode_dns_qname(raw)
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
