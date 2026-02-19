# frozen_string_literal: true

module UniKey
  class Configuration
    # How long to cache DNS lookups (in seconds)
    attr_accessor :dns_cache_ttl

    # Maximum age of requests (in seconds) - prevents replay attacks
    attr_accessor :max_request_age

    # Trusted signer domains (optional whitelist)
    attr_accessor :trusted_signers

    # RFC-002 DNS Hardening
    attr_accessor :dns_hardening_enabled

    # Custom DNS resolvers for hardened lookups (default: Google, Cloudflare, Quad9)
    attr_accessor :dns_resolvers

    # Minimum number of resolvers that must agree (default: 2)
    attr_accessor :dns_min_consistent

    # Optional logger
    attr_accessor :logger

    def initialize
      @dns_cache_ttl = 3600              # 1 hour
      @max_request_age = 300             # 5 minutes
      @trusted_signers = nil             # nil = trust any valid signer
      @dns_hardening_enabled = false     # opt-in to RFC-002
      @dns_resolvers = nil               # use defaults
      @dns_min_consistent = 2            # 2 of 3 must agree
      @logger = nil
    end

    def trusted?(signer_domain)
      return true if @trusted_signers.nil?
      @trusted_signers.include?(signer_domain)
    end
  end
end
