# frozen_string_literal: true

module UniKey
  class Configuration
    # How long to cache DNS lookups (in seconds)
    attr_accessor :dns_cache_ttl

    # Maximum age of requests (in seconds) - prevents replay attacks
    attr_accessor :max_request_age

    # Trusted signer domains (optional whitelist)
    attr_accessor :trusted_signers

    def initialize
      @dns_cache_ttl = 3600      # 1 hour
      @max_request_age = 300     # 5 minutes
      @trusted_signers = nil     # nil = trust any valid signer
    end

    def trusted?(signer_domain)
      return true if @trusted_signers.nil?
      @trusted_signers.include?(signer_domain)
    end
  end
end
