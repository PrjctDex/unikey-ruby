# frozen_string_literal: true

Gem::Specification.new do |spec|
  spec.name          = "unikey"
  spec.version       = "0.1.0"
  spec.authors       = ["UniKey"]
  spec.email         = ["hello@unikey.tech"]

  spec.summary       = "DKIM-based signature verification for AI agent requests"
  spec.description   = "Verify UniKey-signed requests from AI agents. Uses Ed25519 signatures with public keys published in DNS."
  spec.homepage      = "https://unikey.tech"
  spec.license       = "MIT"
  spec.required_ruby_version = ">= 3.0.0"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = "https://github.com/unikey-tech/unikey-ruby"
  spec.metadata["changelog_uri"] = "https://github.com/unikey-tech/unikey-ruby/blob/main/CHANGELOG.md"

  spec.files = Dir.chdir(__dir__) do
    `git ls-files -z`.split("\x0").reject do |f|
      (File.expand_path(f) == __FILE__) ||
        f.start_with?(*%w[bin/ test/ spec/ features/ .git .github appveyor Gemfile])
    end
  end

  spec.require_paths = ["lib"]

  # Runtime dependencies
  spec.add_dependency "ed25519", "~> 1.3"

  # Development dependencies
  spec.add_development_dependency "bundler", "~> 2.0"
  spec.add_development_dependency "rake", "~> 13.0"
  spec.add_development_dependency "rspec", "~> 3.0"
  spec.add_development_dependency "webmock", "~> 3.0"
end
