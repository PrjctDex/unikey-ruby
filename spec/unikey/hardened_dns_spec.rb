# frozen_string_literal: true

require "spec_helper"
require "ed25519"
require "base64"

RSpec.describe UniKey::HardenedDNS do
  let(:signing_key) { Ed25519::SigningKey.generate }
  let(:public_key_b64) { Base64.strict_encode64(signing_key.verify_key.to_bytes) }
  let(:dns_record) { "v=DKIM1; k=ed25519; p=#{public_key_b64}" }
  let(:signer_domain) { "unikey.tech" }
  let(:bad_key) { "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" }
  let(:bad_record) { "v=DKIM1; k=ed25519; p=#{bad_key}" }

  before do
    UniKey.configure do |config|
      config.dns_hardening_enabled = true
      config.dns_resolvers = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]
      config.dns_min_consistent = 2
    end
  end

  def stub_resolver(ip, record_strings)
    resolver = instance_double(Resolv::DNS)
    allow(resolver).to receive(:timeouts=)
    allow(resolver).to receive(:close)

    records = if record_strings
                [double(strings: [record_strings])]
              else
                []
              end
    allow(resolver).to receive(:getresources).and_return(records)
    allow(Resolv::DNS).to receive(:new).with(nameserver: [ip]).and_return(resolver)
  end

  describe ".lookup" do
    context "when all resolvers agree" do
      before do
        %w[8.8.8.8 1.1.1.1 9.9.9.9].each do |ip|
          stub_resolver(ip, dns_record)
        end
      end

      it "returns the public key" do
        result = described_class.lookup(signer_domain)
        expect(result).to eq(public_key_b64)
      end
    end

    context "when 2 of 3 agree (meets minimum)" do
      before do
        stub_resolver("8.8.8.8", dns_record)
        stub_resolver("1.1.1.1", dns_record)
        stub_resolver("9.9.9.9", bad_record)
      end

      it "returns the consensus key" do
        result = described_class.lookup(signer_domain)
        expect(result).to eq(public_key_b64)
      end
    end

    context "when resolvers disagree (below minimum)" do
      before do
        UniKey.configure do |c|
          c.dns_hardening_enabled = true
          c.dns_resolvers = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]
          c.dns_min_consistent = 3
        end

        stub_resolver("8.8.8.8", dns_record)
        stub_resolver("1.1.1.1", dns_record)
        stub_resolver("9.9.9.9", bad_record)
      end

      it "raises DNSInconsistency" do
        expect { described_class.lookup(signer_domain) }.to raise_error(UniKey::DNSInconsistency)
      end
    end

    context "when all resolvers fail" do
      before do
        %w[8.8.8.8 1.1.1.1 9.9.9.9].each do |ip|
          stub_resolver(ip, nil)
        end
      end

      it "raises DNSLookupFailed" do
        expect { described_class.lookup(signer_domain) }.to raise_error(UniKey::DNSLookupFailed)
      end
    end

    context "with caching" do
      before do
        %w[8.8.8.8 1.1.1.1 9.9.9.9].each do |ip|
          stub_resolver(ip, dns_record)
        end
      end

      it "caches results" do
        result1 = described_class.lookup(signer_domain)
        result2 = described_class.lookup(signer_domain)

        expect(result1).to eq(result2)
        expect(result1).to eq(public_key_b64)
      end
    end
  end
end
