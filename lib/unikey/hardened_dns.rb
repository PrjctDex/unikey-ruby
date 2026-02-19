# frozen_string_literal: true

require "resolv"
require "base64"

module UniKey
  # RFC-002 DNS Hardening - Multi-resolver validation with caching
  #
  # Instead of trusting a single DNS resolver, queries 3+ resolvers
  # and requires consistency. Fail-closed on disagreement.
  #
  # @example
  #   UniKey.configure do |config|
  #     config.dns_hardening_enabled = true
  #     config.dns_resolvers = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]
  #     config.dns_min_consistent = 2  # At least 2 must agree
  #   end
  #
  class HardenedDNS
    # Default public DNS resolvers
    DEFAULT_RESOLVERS = %w[
      8.8.8.8
      1.1.1.1
      9.9.9.9
    ].freeze

    class << self
      # Look up public key with multi-resolver validation
      #
      # @param signer_domain [String] domain to look up
      # @return [String] base64-encoded public key
      # @raise [DNSLookupFailed] if lookup fails or resolvers disagree
      def lookup(signer_domain)
        cached = cache.read(signer_domain)
        return cached if cached

        public_key = fetch_with_hardening(signer_domain)
        cache.write(signer_domain, public_key)
        public_key
      end

      def clear_cache
        cache.clear
      end

      private

      def cache
        @cache ||= DNS::Cache.new
      end

      def resolvers
        UniKey.configuration.dns_resolvers || DEFAULT_RESOLVERS
      end

      def min_consistent
        UniKey.configuration.dns_min_consistent || 2
      end

      def fetch_with_hardening(signer_domain)
        dns_name = "unikey._domainkey.#{signer_domain}"
        results = {}
        errors = []

        # Query each resolver
        resolvers.each do |resolver_ip|
          begin
            result = query_resolver(dns_name, resolver_ip)
            results[resolver_ip] = result if result
          rescue StandardError => e
            errors << { resolver: resolver_ip, error: e.message }
          end
        end

        # Fail if no results
        if results.empty?
          raise DNSLookupFailed.new(signer_domain)
        end

        # Check consistency - group by public key value
        key_groups = results.group_by { |_, key| key }
        best_group = key_groups.max_by { |_, entries| entries.size }
        consensus_key = best_group[0]
        agreement_count = best_group[1].size

        # Fail-closed: require minimum agreement
        if agreement_count < min_consistent
          raise DNSInconsistency.new(
            signer_domain,
            expected: min_consistent,
            got: agreement_count,
            total: results.size
          )
        end

        # Log disagreements (but proceed if we have enough agreement)
        if key_groups.size > 1 && UniKey.configuration.respond_to?(:logger) && UniKey.configuration.logger
          UniKey.configuration.logger.warn(
            "DNS disagreement for #{dns_name}: #{key_groups.size} different keys from #{results.size} resolvers"
          )
        end

        consensus_key
      end

      def query_resolver(dns_name, resolver_ip)
        resolver = Resolv::DNS.new(nameserver: [resolver_ip])
        resolver.timeouts = 3 # 3 second timeout per resolver

        txt_records = resolver.getresources(dns_name, Resolv::DNS::Resource::IN::TXT)
        return nil if txt_records.empty?

        txt_value = txt_records.first.strings.join
        parse_dkim_record(txt_value)
      ensure
        resolver&.close
      end

      def parse_dkim_record(txt)
        match = txt.match(/p=([A-Za-z0-9+\/=]+)/)
        return nil unless match
        match[1]
      end
    end
  end
end
