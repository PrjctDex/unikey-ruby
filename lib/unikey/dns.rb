# frozen_string_literal: true

require "resolv"
require "base64"

module UniKey
  # DNS lookup for UniKey public keys
  class DNS
    class << self
      # Look up the public key for a signer domain
      #
      # @param signer_domain [String] The domain that signed the request
      # @return [String] Base64-encoded Ed25519 public key
      # @raise [DNSLookupFailed] If lookup fails
      def lookup(signer_domain)
        cached = cache.read(signer_domain)
        return cached if cached

        public_key = fetch_from_dns(signer_domain)
        cache.write(signer_domain, public_key)
        public_key
      end

      # Clear the DNS cache
      def clear_cache
        cache.clear
      end

      private

      def cache
        @cache ||= Cache.new
      end

      def fetch_from_dns(signer_domain)
        dns_name = "unikey._domainkey.#{signer_domain}"

        txt_records = Resolv::DNS.open do |dns|
          dns.getresources(dns_name, Resolv::DNS::Resource::IN::TXT)
        end

        raise DNSLookupFailed.new(signer_domain) if txt_records.empty?

        # Parse DKIM-style TXT record
        txt_value = txt_records.first.strings.join
        parse_dkim_record(txt_value, signer_domain)
      end

      def parse_dkim_record(txt, signer_domain)
        # Format: v=DKIM1; k=ed25519; p=BASE64_PUBLIC_KEY
        match = txt.match(/p=([A-Za-z0-9+\/=]+)/)
        raise DNSLookupFailed.new(signer_domain) unless match

        match[1]
      end
    end

    # Simple in-memory cache with TTL
    class Cache
      Entry = Struct.new(:value, :expires_at)

      def initialize
        @entries = {}
        @mutex = Mutex.new
      end

      def read(key)
        @mutex.synchronize do
          entry = @entries[key]
          return nil unless entry
          return nil if entry.expires_at < Time.now

          entry.value
        end
      end

      def write(key, value)
        @mutex.synchronize do
          ttl = UniKey.configuration.dns_cache_ttl
          @entries[key] = Entry.new(value, Time.now + ttl)
        end
      end

      def clear
        @mutex.synchronize do
          @entries.clear
        end
      end
    end
  end
end
