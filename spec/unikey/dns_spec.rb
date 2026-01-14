# frozen_string_literal: true

require "spec_helper"

RSpec.describe UniKey::DNS do
  let(:signer_domain) { "unikey.tech" }
  let(:public_key_b64) { "dGVzdHB1YmxpY2tleQ==" }
  let(:dns_record) { "v=DKIM1; k=ed25519; p=#{public_key_b64}" }

  describe ".lookup" do
    context "when DNS record exists" do
      before do
        allow(Resolv::DNS).to receive(:open).and_yield(
          double(getresources: [double(strings: [dns_record])])
        )
      end

      it "returns the public key" do
        result = described_class.lookup(signer_domain)
        expect(result).to eq(public_key_b64)
      end

      it "caches the result" do
        # First lookup
        described_class.lookup(signer_domain)

        # Second lookup should use cache, not DNS
        expect(Resolv::DNS).not_to receive(:open)
        described_class.lookup(signer_domain)
      end
    end

    context "when DNS record does not exist" do
      before do
        allow(Resolv::DNS).to receive(:open).and_yield(
          double(getresources: [])
        )
      end

      it "raises DNSLookupFailed" do
        expect { described_class.lookup(signer_domain) }
          .to raise_error(UniKey::DNSLookupFailed)
      end
    end
  end

  describe ".clear_cache" do
    it "clears the cache" do
      allow(Resolv::DNS).to receive(:open).and_yield(
        double(getresources: [double(strings: [dns_record])])
      )

      # Populate cache
      described_class.lookup(signer_domain)

      # Clear cache
      described_class.clear_cache

      # Should hit DNS again
      expect(Resolv::DNS).to receive(:open).and_yield(
        double(getresources: [double(strings: [dns_record])])
      )
      described_class.lookup(signer_domain)
    end
  end
end
