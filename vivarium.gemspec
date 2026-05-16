# frozen_string_literal: true

require_relative "lib/vivarium/version"

Gem::Specification.new do |spec|
  spec.name = "vivarium"
  spec.version = Vivarium::VERSION
  spec.authors = ["Uchio Kondo"]
  spec.email = ["udzura@udzura.jp"]

  spec.summary = "Ruby observation and sandbox helper with RbBCC + TracePoint"
  spec.description = "Vivarium visualizes low-level events such as file open paths and relates them to Ruby method boundaries by combining RbBCC (eBPF LSM) and TracePoint."
  spec.homepage = "https://github.com/udzura/vivarium"
  spec.required_ruby_version = ">= 3.3.0"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = spec.homepage
  spec.metadata["changelog_uri"] = "#{spec.homepage}/blob/main/README.md"
  spec.metadata["bug_tracker_uri"] = "#{spec.homepage}/issues"

  # Specify which files should be added to the gem when it is released.
  # The `git ls-files -z` loads the files in the RubyGem that have been added into git.
  gemspec = File.basename(__FILE__)
  spec.files = IO.popen(%w[git ls-files -z], chdir: __dir__, err: IO::NULL) do |ls|
    ls.readlines("\x0", chomp: true).reject do |f|
      (f == gemspec) ||
        f.start_with?(*%w[bin/ Gemfile .gitignore test/ .github/])
    end
  end
  spec.bindir = "exe"
  spec.executables = spec.files.grep(%r{\Aexe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_dependency "rbbcc", "~> 0.11.3"
end
