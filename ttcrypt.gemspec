# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'ttcrypt/version'
require 'rake'
require "rake/extensiontask"
require 'rubygems/package_task'

spec = Gem::Specification.new do |spec|
  spec.name          = "TTCrypt"
  spec.version       = TTCrypt::VERSION
  spec.authors       = ["sergeych"]
  spec.email         = ["real.sergeych@gmail.com"]
  spec.summary       = %q{thrift basic cryptography}
  spec.description   = %q{optimized basic cryptography primitives in c++}
  spec.homepage      = ""
  spec.license       = "GPL3+"

  spec.files         = `git ls-files -z`.split("\x0")
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = ["lib"]

  spec.extensions = FileList["ext/**/extconf.rb"]

  spec.platform = Gem::Platform::RUBY

  spec.add_development_dependency "bundler", "~> 1.6"
  spec.add_development_dependency "rake"
  spec.add_development_dependency "rake-compiler"
  spec.add_development_dependency "rspec", '>= 2.14.0'

  spec.requirements << 'GMP, https://gmplib.org'
end


# add your default gem packing task
Gem::PackageTask.new(spec) do |pkg|
end

Rake::ExtensionTask.new "ttcrypt", spec do |ext|
  ext.lib_dir = "lib/ttcrypt"
  ext.source_pattern = "*.{c,cpp}"
  ext.gem_spec = spec
end

spec
