#!/usr/bin/env ruby
# frozen_string_literal: true

require "vivarium"

# Usage:
#   1) In another shell (root): sudo bundle exec vivariumd
#   2) Run this script: bundle exec ruby examples/box_demo.rb
#
# This demo demonstrates Vivarium::Box usage for automatically tracing
# method calls within an isolated eval context.

FILTER = {
  include_events: %w[span_start span_stop]
}.freeze

# Create a box and define a class within it
box = Vivarium::Box.new

box.eval(<<~RUBY)
  require "net/http"
  class Calculator
    def add(a, b)
      a + b
    end

    def multiply(a, b)
      a * b
    end
  end

  class Greeter
    def greet(name)
      system "echo Hello \#{name}!"
    end
  end

  system "ping -c 1 example.com"
RUBY

box.done_load!

# Enable observation - all Box method calls will be automatically traced
puts "[box-demo] calling box methods with automatic tracing"

# Access classes defined in the box through const_missing
calc = box::Calculator.new
result1 = calc.add(10, 20)
puts "[box-demo] calc.add(10, 20) = #{result1}"

result2 = calc.multiply(3, 4)
puts "[box-demo] calc.multiply(3, 4) = #{result2}"

greeter = box::Greeter.new
greeting = greeter.greet("World")
puts "[box-demo] greeter.greet('World') = #{greeting}"

puts "[box-demo] done"

