# frozen_string_literal: true

require "test_helper"

class VivariumObservationApiTest < Test::Unit::TestCase
  test "observe without block is supported" do
    err = assert_raise(Vivarium::Error) do
      Vivarium.observe(pin_dir: "/tmp/vivarium-not-found")
    end
    assert_match(/failed to open pinned maps/, err.message)
  end

  test "observe accepts filter keyword" do
    err = assert_raise(Vivarium::Error) do
      Vivarium.observe(
        pin_dir: "/tmp/vivarium-not-found",
        filter: { include_events: ["path_open"] }
      )
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
