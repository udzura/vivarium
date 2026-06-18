# frozen_string_literal: true

require "test_helper"

class VivariumObservationApiTest < Test::Unit::TestCase
  MISSING_SOCKET = "/tmp/vivarium-not-found.sock"

  test "observe without block raises when daemon socket is absent" do
    err = assert_raise(Vivarium::Error) do
      Vivarium.observe(socket_path: MISSING_SOCKET)
    end
    assert_match(/cannot connect to vivariumd/, err.message)
  end

  test "observe accepts filter keyword" do
    err = assert_raise(Vivarium::Error) do
      Vivarium.observe(
        socket_path: MISSING_SOCKET,
        filter: { include_events: ["path_open"] }
      )
    end
    assert_match(/cannot connect to vivariumd/, err.message)
  end

  test "top_observe exists" do
    assert_respond_to Vivarium, :top_observe
  end

  test "daemon client reports unhealthy when socket is missing" do
    client = Vivarium::DaemonClient.new(socket_path: MISSING_SOCKET)
    assert_equal false, client.healthy?
  end

  test "daemon client raises readable error when socket is missing" do
    client = Vivarium::DaemonClient.new(socket_path: MISSING_SOCKET)
    err = assert_raise(Vivarium::Error) do
      client.register(Process.pid)
    end
    assert_match(/cannot connect to vivariumd/, err.message)
  end
end
