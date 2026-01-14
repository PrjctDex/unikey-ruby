# frozen_string_literal: true

require "ed25519"
require "base64"
require "digest"
require "ostruct"

module UniKey
  # Verifies UniKey signatures on incoming requests
  class Verifier
    REQUIRED_HEADERS = %w[
      X-UniKey-Signature
      X-UniKey-Signer
      X-UniKey-Timestamp
      X-UniKey-Body-Hash
      X-Agent-Email
    ].freeze

    class << self
      # Verify a request and return verified info
      #
      # @param request [ActionDispatch::Request, Rack::Request, Hash] The request to verify
      # @return [OpenStruct] Verified request info with signer, agent_email, timestamp
      # @raise [InvalidSignature, ExpiredRequest, MissingHeaders, DNSLookupFailed, UntrustedSigner]
      def verify!(request)
        headers = extract_headers(request)
        body = extract_body(request)

        # Check required headers
        missing = REQUIRED_HEADERS.select { |h| headers[h].nil? || headers[h].empty? }
        raise MissingHeaders.new(missing) unless missing.empty?

        signature = headers["X-UniKey-Signature"]
        signer = headers["X-UniKey-Signer"]
        timestamp = headers["X-UniKey-Timestamp"].to_i
        body_hash = headers["X-UniKey-Body-Hash"]
        agent_email = headers["X-Agent-Email"]

        # Check timestamp freshness (prevent replay)
        max_age = UniKey.configuration.max_request_age
        if Time.now.to_i - timestamp > max_age
          raise ExpiredRequest
        end

        # Check trusted signers
        unless UniKey.configuration.trusted?(signer)
          raise UntrustedSigner.new(signer)
        end

        # Verify body hash
        actual_body_hash = hash_body(body)
        raise InvalidSignature unless secure_compare(body_hash, actual_body_hash)

        # Get public key from DNS
        public_key_b64 = DNS.lookup(signer)
        public_key_bytes = Base64.decode64(public_key_b64)
        verify_key = Ed25519::VerifyKey.new(public_key_bytes)

        # Reconstruct canonical string
        canonical = build_canonical_string(
          method: extract_method(request),
          url: extract_url(request),
          body_hash: body_hash,
          timestamp: timestamp,
          agent_email: agent_email
        )

        # Verify signature
        signature_bytes = Base64.decode64(signature)
        begin
          verify_key.verify(signature_bytes, canonical)
        rescue Ed25519::VerifyError
          raise InvalidSignature
        end

        # Return verified info
        OpenStruct.new(
          signer: signer,
          agent_email: agent_email,
          timestamp: Time.at(timestamp)
        )
      end

      # Verify a request without raising (returns nil on failure)
      #
      # @param request [ActionDispatch::Request, Rack::Request, Hash] The request to verify
      # @return [OpenStruct, nil] Verified request info or nil if verification fails
      def verify(request)
        verify!(request)
      rescue Error
        nil
      end

      private

      def extract_headers(request)
        case request
        when Hash
          # Allow direct hash input for testing
          normalize_headers(request[:headers] || request)
        else
          # Rails/Rack request
          normalize_headers(request_headers(request))
        end
      end

      def normalize_headers(headers)
        normalized = {}
        headers.each do |key, value|
          # Handle both "X-UniKey-Signature" and "HTTP_X_UNIKEY_SIGNATURE" formats
          normalized_key = key.to_s
            .gsub(/^HTTP_/, "")
            .split("_")
            .map(&:capitalize)
            .join("-")
          normalized[normalized_key] = value.to_s
        end
        normalized
      end

      def request_headers(request)
        if request.respond_to?(:headers)
          request.headers.to_h
        elsif request.respond_to?(:env)
          request.env.select { |k, _| k.start_with?("HTTP_") }
        else
          {}
        end
      end

      def extract_body(request)
        case request
        when Hash
          request[:body] || ""
        else
          if request.respond_to?(:raw_post)
            request.raw_post
          elsif request.respond_to?(:body)
            body = request.body
            body.respond_to?(:read) ? body.read.tap { body.rewind rescue nil } : body.to_s
          else
            ""
          end
        end
      end

      def extract_method(request)
        case request
        when Hash
          request[:method] || "POST"
        else
          request.respond_to?(:request_method) ? request.request_method : "POST"
        end
      end

      def extract_url(request)
        case request
        when Hash
          request[:url] || ""
        else
          if request.respond_to?(:original_url)
            request.original_url
          elsif request.respond_to?(:url)
            request.url
          else
            ""
          end
        end
      end

      def hash_body(body)
        body_str = body.is_a?(Hash) ? JSON.generate(body) : body.to_s
        Base64.strict_encode64(Digest::SHA256.digest(body_str))
      end

      def build_canonical_string(method:, url:, body_hash:, timestamp:, agent_email:)
        [
          method.to_s.upcase,
          url.to_s,
          body_hash.to_s,
          timestamp.to_s,
          agent_email.to_s
        ].join("\n")
      end

      # Constant-time string comparison to prevent timing attacks
      def secure_compare(a, b)
        return false if a.nil? || b.nil?
        return false unless a.bytesize == b.bytesize

        l = a.unpack("C*")
        r = b.unpack("C*")
        result = 0
        l.zip(r) { |x, y| result |= x ^ y }
        result.zero?
      end
    end
  end
end
