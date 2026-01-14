# frozen_string_literal: true

module UniKey
  # Base error class
  class Error < StandardError; end

  # Raised when signature verification fails
  class InvalidSignature < Error
    def message
      "Invalid UniKey signature"
    end
  end

  # Raised when request is too old (replay attack prevention)
  class ExpiredRequest < Error
    def message
      "Request has expired"
    end
  end

  # Raised when required headers are missing
  class MissingHeaders < Error
    attr_reader :missing

    def initialize(missing)
      @missing = missing
      super()
    end

    def message
      "Missing required headers: #{@missing.join(', ')}"
    end
  end

  # Raised when DNS lookup fails
  class DNSLookupFailed < Error
    attr_reader :domain

    def initialize(domain)
      @domain = domain
      super()
    end

    def message
      "Failed to lookup public key for #{@domain}"
    end
  end

  # Raised when signer is not trusted
  class UntrustedSigner < Error
    attr_reader :signer

    def initialize(signer)
      @signer = signer
      super()
    end

    def message
      "Signer '#{@signer}' is not trusted"
    end
  end
end
