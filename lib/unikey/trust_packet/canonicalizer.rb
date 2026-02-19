# frozen_string_literal: true

require "json"
require "digest"
require "base64"

module UniKey
  class TrustPacket
    # RFC-001 §4 Canonicalization
    #
    # Produces a deterministic byte representation of a trust packet
    # for signing and verification.
    #
    # Rules:
    #   - Lexicographic key ordering (recursive)
    #   - UTF-8 encoding
    #   - No whitespace between tokens
    #   - Deterministic JSON serialization
    #
    module Canonicalizer
      module_function

      # Canonicalize a hash into a deterministic JSON string
      #
      # @param data [Hash] the unsigned packet data (header, claims, payload)
      # @return [String] canonical JSON string
      def canonicalize(data)
        sorted = sort_recursive(stringify_keys(data))
        JSON.generate(sorted)
      end

      # SHA-256 hash of canonical form, base64 encoded
      #
      # @param data [Hash] the unsigned packet data
      # @return [String] base64-encoded SHA-256 hash
      def hash(data)
        canonical = canonicalize(data)
        Base64.strict_encode64(Digest::SHA256.digest(canonical))
      end

      # @private
      def sort_recursive(obj)
        case obj
        when Hash
          obj.sort.to_h.transform_values { |v| sort_recursive(v) }
        when Array
          obj.map { |item| sort_recursive(item) }
        else
          obj
        end
      end

      # @private
      def stringify_keys(obj)
        case obj
        when Hash
          obj.each_with_object({}) do |(k, v), result|
            result[k.to_s] = stringify_keys(v)
          end
        when Array
          obj.map { |item| stringify_keys(item) }
        when Symbol
          obj.to_s
        else
          obj
        end
      end
    end
  end
end
