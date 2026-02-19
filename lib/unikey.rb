# frozen_string_literal: true

require_relative "unikey/version"
require_relative "unikey/configuration"
require_relative "unikey/errors"
require_relative "unikey/dns"
require_relative "unikey/hardened_dns"
require_relative "unikey/verifier"
require_relative "unikey/trust_packet"

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

    # ============== HTTP Request Verification ==============

    # Verify a signed HTTP request (raises on failure)
    def verify!(request)
      Verifier.verify!(request)
    end

    # Verify a signed HTTP request (returns nil on failure)
    def verify(request)
      Verifier.verify(request)
    end

    # ============== Trust Packet API ==============

    # Build and sign a Trust Packet
    #
    # @example
    #   packet = UniKey.build_packet(
    #     subject: "claude@user.example.com",
    #     audience: "orders@acme-store.com",
    #     action: "purchase_item",
    #     scope: ["purchase:items"],
    #     params: { item: "blue purse", callback_url: "https://device/cb/123" },
    #     signing_key: my_key,
    #     signer_domain: "user.example.com"
    #   )
    def build_packet(**args)
      TrustPacket.build(**args)
    end

    # Verify a Trust Packet (raises on failure)
    def verify_packet!(packet_data)
      TrustPacket.verify!(packet_data)
    end

    # Verify a Trust Packet (returns nil on failure)
    def verify_packet(packet_data)
      TrustPacket.verify(packet_data)
    end

    # Parse a Trust Packet from hash/JSON
    def parse_packet(data)
      case data
      when String then TrustPacket.from_json(data)
      when Hash then TrustPacket.from_hash(data)
      else raise ArgumentError, "Expected Hash or JSON String"
      end
    end
  end
end
