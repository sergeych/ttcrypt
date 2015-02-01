require "bundler/gem_tasks"
require "rake/extensiontask"
require 'rubygems/package_task'

begin
  bundle..setup(:default, :development)
rescue bundler::bundlererror => e
  $stderr.puts e.message
  $stderr.puts "Run `bundle install` to install missing gems"
  exit e.status_code
end

$gemspec = Bundler::GemHelper.gemspec
+
Gem::PackageTask.new($gemspec) do |pkg|
  end
end

Rake::ExtensionTask.new "ttcrypt" do |ext|
  ext.lib_dir = "lib/ttcrypt"
  ext.source_pattern = "*.{c,cpp}"
  ext.gem_spec = gemspec
end


