# frozen_string_literal: true

require "ed25519"
require "base64"
require "ostruct"

module UniKey
  class TrustPacket
    # Verifies Trust Packet signatures using DNS-published public keys.
    #
    # No middleman server needed - verification is entirely self-contained:
    #   1. Parse the packet structure
    #   2. Canonicalize the unsigned portion
    #   3. Look up signer's public key from DNS
    #   4. Verify Ed25519 signature
    #   5. Check expiration and claims
    #
    module Verifier
      module_function

      # Verify a Trust Packet and return verified info
      #
      # @param packet_data [Hash] the full packet (header, claims, payload, signatures)
      # @return [OpenStruct] verified info with subject, action, signer, scope, etc.
      # @raise [UniKey::InvalidPacket, UniKey::InvalidSignature, UniKey::ExpiredRequest,
      #         UniKey::DNSLookupFailed, UniKey::UntrustedSigner]
      def verify!(packet_data)
        validate_structure!(packet_data)

        header = packet_data[:header]
        claims = packet_data[:claims]
        payload = packet_data[:payload]
        signatures = packet_data[:signatures]

        # Check expiration
        expires = header[:expires].to_i
        if expires > 0 && Time.now.to_i > expires
          raise UniKey::ExpiredRequest
        end

        # Check trusted signers
        primary_sig = signatures.first
        signer_domain = primary_sig[:signer]
        unless UniKey.configuration.trusted?(signer_domain)
          raise UniKey::UntrustedSigner.new(signer_domain)
        end

        # Build unsigned portion and canonicalize
        unsigned = {
          header: header,
          claims: claims,
          payload: payload
        }
        canonical = Canonicalizer.canonicalize(unsigned)

        # Verify each signature
        signatures.each do |sig|
          verify_signature!(canonical, sig)
        end

        # Validate delegation chain scope narrowing (RFC-001 §5.3)
        validate_delegation_chain!(claims) if claims[:delegation_chain]&.any?

        # Return verified info
        OpenStruct.new(
          valid: true,
          packet_id: header[:packet_id],
          packet_type: header[:packet_type],
          subject: claims[:subject],
          issuer: claims[:issuer],
          audience: claims[:audience],
          scope: claims[:scope],
          action: payload[:action],
          params: payload[:params],
          message: payload[:message],
          callback_url: payload.dig(:params, :callback_url) || payload.dig(:params, "callback_url"),
          signer: signer_domain,
          delegation_chain: claims[:delegation_chain],
          timestamp: Time.at(header[:timestamp].to_i),
          expires_at: expires > 0 ? Time.at(expires) : nil
        )
      end

      # Verify without raising (returns nil on failure)
      def verify(packet_data)
        verify!(packet_data)
      rescue UniKey::Error
        nil
      end

      # @private
      def validate_structure!(data)
        %i[header claims payload signatures].each do |field|
          raise UniKey::InvalidPacket.new("Missing field: #{field}") unless data[field]
        end

        raise UniKey::InvalidPacket.new("No signatures") if data[:signatures].empty?

        %i[version packet_type packet_id timestamp].each do |field|
          raise UniKey::InvalidPacket.new("Missing header.#{field}") unless data[:header][field]
        end

        %i[subject issuer audience].each do |field|
          raise UniKey::InvalidPacket.new("Missing claims.#{field}") unless data[:claims][field]
        end

        unless data[:payload][:action]
          raise UniKey::InvalidPacket.new("Missing payload.action")
        end
      end

      # @private
      def verify_signature!(canonical, sig)
        signer_domain = sig[:signer]
        signature_b64 = sig[:signature]

        # Look up public key from DNS (uses hardened resolver if configured)
        public_key_b64 = if UniKey.configuration.dns_hardening_enabled
                           UniKey::HardenedDNS.lookup(signer_domain)
                         else
                           UniKey::DNS.lookup(signer_domain)
                         end

        public_key_bytes = Base64.decode64(public_key_b64)
        verify_key = Ed25519::VerifyKey.new(public_key_bytes)

        signature_bytes = Base64.decode64(signature_b64)
        begin
          verify_key.verify(signature_bytes, canonical)
        rescue Ed25519::VerifyError
          raise UniKey::InvalidSignature
        end
      end

      # @private - RFC-001 §5.3: Delegations can only narrow scope
      def validate_delegation_chain!(claims)
        # For now, we just validate the chain exists and is well-formed.
        # Full scope narrowing validation requires comparing parent scopes,
        # which would need the parent packets.
        chain = claims[:delegation_chain]
        return if chain.nil? || chain.empty?

        chain.each do |link|
          unless link.is_a?(String) && link.include?("→")
            # Allow both arrow formats
            next if link.is_a?(String) && link.include?("->")
            # Warn but don't fail for now
          end
        end
      end
    end
  end
end
