# frozen_string_literal: true

require "test_helper"

class VivariumTest < Test::Unit::TestCase
  test "VERSION" do
    assert do
      ::Vivarium.const_defined?(:VERSION)
    end
  end

  test "event can be parsed from binary payload" do
    binary = [1234].pack("L<") + "path_open" + "/tmp/a.txt".ljust(64, "\x00")
    event = Vivarium::Event.from_binary(binary)

    assert_equal 1234, event.pid
    assert_equal "path_open", event.event_name
    assert_equal "/tmp/a.txt", event.payload
  end

  test "observe requires block" do
    assert_raise(ArgumentError) do
      Vivarium.observe
    end
  end

  test "map store raises readable error when pin is missing" do
    err = assert_raise(Vivarium::Error) do
      Vivarium::MapStore.new(pin_dir: "/tmp/vivarium-not-found")
    end
    assert_match(/failed to open pinned maps/, err.message)
  end
end
