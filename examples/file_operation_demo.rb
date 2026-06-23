#!/usr/bin/env ruby
# frozen_string_literal: true

require "fileutils"
require "tmpdir"
require "vivarium"

# Usage:
#   1) In another shell (root): sudo bundle exec vivariumd
#   2) Run this script: bundle exec ruby examples/file_operation_demo.rb

TMP_PREFIX = "vivarium-file-demo"
FILTER = {
  include_events: %w[path_open file_symlink file_hardlink file_rename file_chmod file_unlink file_getdents]
}.freeze

def try_step(title)
  puts "[file-demo] #{title}"
  yield
rescue StandardError => e
  puts "[file-demo] #{title} failed: #{e.class}: #{e.message}"
end

Dir.mktmpdir(TMP_PREFIX, "/tmp") do |dir|
  source_path = File.join(dir, "source.txt")
  renamed_path = File.join(dir, "renamed.txt")
  hardlink_path = File.join(dir, "hardlink.txt")
  symlink_path = File.join(dir, "symlink.txt")

  Vivarium.observe(filter: FILTER) do
    try_step("create source file") do
      File.write(source_path, "vivarium sample\n")
      File.read(source_path)
    end

    try_step("directory listing") do
      Dir.children(dir)
    end

    try_step("rename file") do
      File.rename(source_path, renamed_path)
      File.read(renamed_path)
    end

    try_step("create hardlink") do
      File.link(renamed_path, hardlink_path)
      File.read(hardlink_path)
    end

    try_step("create symlink") do
      File.symlink(renamed_path, symlink_path)
      File.read(symlink_path)
    end

    try_step("chmod file") do
      File.chmod(0o640, renamed_path)
      File.stat(renamed_path)
    end

    try_step("unlink hardlink") do
      File.unlink(hardlink_path)
    end

    try_step("unlink symlink") do
      File.unlink(symlink_path)
    end

    try_step("list directory again") do
      Dir.children(dir)
    end
  end

  FileUtils.rm_f(symlink_path)
  FileUtils.rm_f(hardlink_path)
  FileUtils.rm_f(renamed_path)
  FileUtils.rm_f(source_path)
end

puts "[file-demo] done"
