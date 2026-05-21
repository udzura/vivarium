# frozen_string_literal: true

require "optparse"

module Vivarium
  module CLI
    def self.run!(argv = ARGV)
      options = { pin_dir: Vivarium.bpf_pin_dir, format: :human, dest: $stdout }
      parser = OptionParser.new do |opts|
        opts.banner = "Usage: vivarium [options] <command> [args]"
        opts.separator ""
        opts.separator "Commands:"
        opts.separator "  load <script>    Load and observe a Ruby script"
        opts.separator ""
        opts.separator "Options:"
        opts.on("--pin-dir PATH", "Pinned map directory") { |v| options[:pin_dir] = v }
        opts.on("--format FORMAT", "Output format (human/json)") { |v| options[:format] = v.to_sym }
        opts.on("-o", "--output PATH", "Log output file (default: stdout)") { |v| options[:dest] = File.open(v, "a") }
      end
      parser.order!(argv)

      command = argv.shift
      case command
      when "load"
        run_load!(argv, options)
      else
        abort parser.help
      end
    end

    def self.run_load!(argv, options)
      script = argv.shift
      abort "Usage: vivarium load <script>" unless script
      abort "File not found: #{script}" unless File.exist?(script)

      Vivarium.observe(pin_dir: options[:pin_dir], format: options[:format], dest: options[:dest]) do
        Kernel.load(File.expand_path(script))
      end
    end
  end
end
