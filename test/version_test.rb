# frozen_string_literal: true

require "test_helper"

class VivariumVersionTest < Test::Unit::TestCase
  test "VERSION" do
    assert do
      ::Vivarium.const_defined?(:VERSION)
    end
  end
end
