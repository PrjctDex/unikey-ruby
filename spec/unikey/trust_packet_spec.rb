# frozen_string_literal: true

require "spec_helper"
require "ed25519"
require "base64"
require "json"

RSpec.describe UniKey::TrustPacket do
  let(:signing_key) { Ed25519::SigningKey.generate }
  let(:verify_key) { signing_key.verify_key }
  let(:public_key_b64) { Base64.strict_encode64(verify_key.to_bytes) }
  let(:signer_domain) { "user.example.com" }

  let(:packet_args) do
    {
      subject: "claude@user.example.com",
      audience: "orders@acme-store.com",
      action: "purchase_item",
      scope: ["purchase:items", "spend:150"],
      params: {
        item: "blue purse",
        max_price: 150,
        callback_url: "https://device.example.com/callbacks/abc123"
      },
      message: "Please purchase a blue purse for my girlfriend.",
      signing_key: signing_key,
      signer_domain: signer_domain
    }
  end

  before do
    dns_record = "v=DKIM1; k=ed25519; p=#{public_key_b64}"
    allow(Resolv::DNS).to receive(:open).and_yield(
      double(getresources: [double(strings: [dns_record])])
    )
  end

  describe ".build" do
    it "creates a valid trust packet" do
      packet = described_class.build(**packet_args)

      expect(packet.header.version).to eq("1.0")
      expect(packet.header.packet_type).to eq("action_request")
      expect(packet.header.packet_id).to start_with("pkt_")
      expect(packet.claims.subject).to eq("claude@user.example.com")
      expect(packet.claims.audience).to eq("orders@acme-store.com")
      expect(packet.claims.scope).to eq(["purchase:items", "spend:150"])
      expect(packet.payload.action).to eq("purchase_item")
      expect(packet.payload.params[:callback_url]).to eq("https://device.example.com/callbacks/abc123")
      expect(packet.signatures.size).to eq(1)
      expect(packet.signatures.first.signer).to eq(signer_domain)
    end

    it "sets expiration based on TTL" do
      packet = described_class.build(**packet_args, ttl: 600)

      expect(packet.header.expires).to eq(packet.header.timestamp + 600)
    end

    it "serializes to hash" do
      packet = described_class.build(**packet_args)
      hash = packet.to_h

      expect(hash).to have_key(:header)
      expect(hash).to have_key(:claims)
      expect(hash).to have_key(:payload)
      expect(hash).to have_key(:signatures)
    end

    it "serializes to JSON" do
      packet = described_class.build(**packet_args)
      json = packet.to_json

      parsed = JSON.parse(json)
      expect(parsed["header"]["version"]).to eq("1.0")
      expect(parsed["claims"]["subject"]).to eq("claude@user.example.com")
    end
  end

  describe ".verify!" do
    let(:packet) { described_class.build(**packet_args) }
    let(:packet_hash) { packet.to_h }

    it "verifies a valid packet" do
      result = described_class.verify!(packet_hash)

      expect(result.valid).to eq(true)
      expect(result.subject).to eq("claude@user.example.com")
      expect(result.audience).to eq("orders@acme-store.com")
      expect(result.action).to eq("purchase_item")
      expect(result.signer).to eq(signer_domain)
      expect(result.callback_url).to eq("https://device.example.com/callbacks/abc123")
    end

    it "verifies a packet from JSON round-trip" do
      json = packet.to_json
      parsed = JSON.parse(json)
      result = described_class.verify!(parsed)

      expect(result.valid).to eq(true)
      expect(result.subject).to eq("claude@user.example.com")
    end

    context "with expired packet" do
      let(:packet) { described_class.build(**packet_args, ttl: -10) }

      it "raises ExpiredRequest" do
        expect { described_class.verify!(packet_hash) }.to raise_error(UniKey::ExpiredRequest)
      end
    end

    context "with tampered payload" do
      it "raises InvalidSignature" do
        tampered = packet_hash
        tampered[:payload][:action] = "steal_everything"

        expect { described_class.verify!(tampered) }.to raise_error(UniKey::InvalidSignature)
      end
    end

    context "with missing structure" do
      it "raises InvalidPacket when signatures missing" do
        bad = packet_hash.dup
        bad.delete(:signatures)

        expect { described_class.verify!(bad) }.to raise_error(UniKey::InvalidPacket)
      end

      it "raises InvalidPacket when header fields missing" do
        bad = packet_hash.dup
        bad[:header].delete(:version)

        expect { described_class.verify!(bad) }.to raise_error(UniKey::InvalidPacket)
      end
    end

    context "with untrusted signer" do
      before do
        UniKey.configure { |c| c.trusted_signers = ["other.com"] }
      end

      it "raises UntrustedSigner" do
        expect { described_class.verify!(packet_hash) }.to raise_error(UniKey::UntrustedSigner)
      end
    end
  end

  describe ".verify" do
    let(:packet) { described_class.build(**packet_args) }

    it "returns result for valid packet" do
      result = described_class.verify(packet.to_h)
      expect(result).not_to be_nil
      expect(result.valid).to eq(true)
    end

    it "returns nil for invalid packet" do
      bad = packet.to_h
      bad[:payload][:action] = "tampered"
      expect(described_class.verify(bad)).to be_nil
    end
  end

  describe ".from_hash / .from_json" do
    let(:packet) { described_class.build(**packet_args) }

    it "parses from hash" do
      parsed = described_class.from_hash(packet.to_h)

      expect(parsed.header.version).to eq("1.0")
      expect(parsed.claims.subject).to eq("claude@user.example.com")
      expect(parsed.payload.action).to eq("purchase_item")
    end

    it "parses from JSON" do
      parsed = described_class.from_json(packet.to_json)

      expect(parsed.header.version).to eq("1.0")
      expect(parsed.claims.subject).to eq("claude@user.example.com")
    end
  end

  describe "Canonicalizer" do
    it "produces deterministic output" do
      data_a = { b: 2, a: 1, c: { z: 26, a: 1 } }
      data_b = { c: { a: 1, z: 26 }, a: 1, b: 2 }

      expect(
        UniKey::TrustPacket::Canonicalizer.canonicalize(data_a)
      ).to eq(
        UniKey::TrustPacket::Canonicalizer.canonicalize(data_b)
      )
    end

    it "sorts keys lexicographically" do
      result = UniKey::TrustPacket::Canonicalizer.canonicalize({ z: 1, a: 2, m: 3 })
      parsed = JSON.parse(result)
      expect(parsed.keys).to eq(["a", "m", "z"])
    end

    it "produces consistent hash" do
      data = { action: "test", params: { x: 1 } }
      hash1 = UniKey::TrustPacket::Canonicalizer.hash(data)
      hash2 = UniKey::TrustPacket::Canonicalizer.hash(data)

      expect(hash1).to eq(hash2)
      expect(hash1).to be_a(String)
      expect(Base64.decode64(hash1).length).to eq(32) # SHA-256
    end
  end

  describe "delegation chain" do
    let(:packet) do
      described_class.build(
        **packet_args,
        delegation_chain: [
          "user@gmail.com → personal-agent@agents.example.com",
          "personal-agent@agents.example.com → shopping-bot@agents.example.com"
        ]
      )
    end

    it "includes delegation chain in packet" do
      expect(packet.claims.delegation_chain.size).to eq(2)
    end

    it "verifies packet with delegation chain" do
      result = described_class.verify!(packet.to_h)
      expect(result.delegation_chain.size).to eq(2)
    end
  end

  describe "callback_url" do
    it "extracts callback_url from params" do
      packet = described_class.build(**packet_args)
      result = described_class.verify!(packet.to_h)

      expect(result.callback_url).to eq("https://device.example.com/callbacks/abc123")
    end
  end
end
