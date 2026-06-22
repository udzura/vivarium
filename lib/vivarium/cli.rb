# frozen_string_literal: true

require "optparse"

module Vivarium
  module CLI
    def self.run!(argv = ARGV)
      options = { socket_path: Vivarium.socket_path, dest: $stdout }
      parser = OptionParser.new do |opts|
        opts.banner = "Usage: vivarium [options] <command> [args]"
        opts.separator ""
        opts.separator "Commands:"
        opts.separator "  load <script>    Load and observe a Ruby script"
        opts.separator ""
        opts.separator "Options:"
        opts.on("--socket PATH", "vivariumd Unix domain socket path") { |v| options[:socket_path] = v }
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

      Vivarium.observe(socket_path: options[:socket_path], dest: options[:dest],
                       filter: Vivarium::DEFAULT_FILTER) do
        Kernel.load(File.expand_path(script))
      end
    end
  end
end
