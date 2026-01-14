# frozen_string_literal: true

require_relative "unikey/version"
require_relative "unikey/configuration"
require_relative "unikey/errors"
require_relative "unikey/dns"
require_relative "unikey/verifier"

# Conditionally load Rails integration
if defined?(Rails)
  require_relative "unikey/rails/controller_helper"
end

module UniKey
  class << self
    attr_writer :configuration

    def configuration
      @configuration ||= Configuration.new
    end

    def configure
      yield(configuration)
    end

    # Convenience method for verifying requests
    def verify!(request)
      Verifier.verify!(request)
    end

    # Convenience method for checking if request is valid (doesn't raise)
    def verify(request)
      Verifier.verify(request)
    end
  end
end
