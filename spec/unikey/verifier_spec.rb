# frozen_string_literal: true

require "spec_helper"
require "ed25519"
require "base64"
require "digest"
require "json"

RSpec.describe UniKey::Verifier do
  # Generate a test keypair
  let(:signing_key) { Ed25519::SigningKey.generate }
  let(:verify_key) { signing_key.verify_key }
  let(:public_key_b64) { Base64.strict_encode64(verify_key.to_bytes) }

  let(:signer_domain) { "unikey.tech" }
  let(:agent_email) { "agent@example.com" }
  let(:timestamp) { Time.now.to_i }
  let(:method) { "POST" }
  let(:url) { "https://example.com/api/agent/balance" }
  let(:body) { { "action" => "get_balance" } }
  let(:body_json) { JSON.generate(body) }
  let(:body_hash) { Base64.strict_encode64(Digest::SHA256.digest(body_json)) }

  let(:canonical_string) do
    [method, url, body_hash, timestamp.to_s, agent_email].join("\n")
  end

  let(:signature) do
    Base64.strict_encode64(signing_key.sign(canonical_string))
  end

  let(:valid_request) do
    {
      method: method,
      url: url,
      body: body_json,
      headers: {
        "X-UniKey-Signature" => signature,
        "X-UniKey-Signer" => signer_domain,
        "X-UniKey-Timestamp" => timestamp.to_s,
        "X-UniKey-Body-Hash" => body_hash,
        "X-Agent-Email" => agent_email
      }
    }
  end

  before do
    # Stub DNS lookup to return our test public key
    dns_record = "v=DKIM1; k=ed25519; p=#{public_key_b64}"
    allow(Resolv::DNS).to receive(:open).and_yield(
      double(getresources: [double(strings: [dns_record])])
    )
  end

  describe ".verify!" do
    context "with valid signature" do
      it "returns verified request info" do
        result = described_class.verify!(valid_request)

        expect(result.signer).to eq(signer_domain)
        expect(result.agent_email).to eq(agent_email)
        expect(result.timestamp).to be_a(Time)
      end
    end

    context "with missing headers" do
      it "raises MissingHeaders" do
        request = valid_request.dup
        request[:headers].delete("X-UniKey-Signature")

        expect { described_class.verify!(request) }.to raise_error(UniKey::MissingHeaders)
      end
    end

    context "with expired timestamp" do
      let(:timestamp) { Time.now.to_i - 600 } # 10 minutes ago

      it "raises ExpiredRequest" do
        expect { described_class.verify!(valid_request) }.to raise_error(UniKey::ExpiredRequest)
      end
    end

    context "with invalid signature" do
      it "raises InvalidSignature" do
        request = valid_request.dup
        request[:headers]["X-UniKey-Signature"] = Base64.strict_encode64("invalid" * 8)

        expect { described_class.verify!(request) }.to raise_error(UniKey::InvalidSignature)
      end
    end

    context "with tampered body" do
      it "raises InvalidSignature" do
        request = valid_request.dup
        request[:body] = '{"action":"tampered"}'

        expect { described_class.verify!(request) }.to raise_error(UniKey::InvalidSignature)
      end
    end

    context "with untrusted signer" do
      before do
        UniKey.configure do |config|
          config.trusted_signers = ["other.com"]
        end
      end

      it "raises UntrustedSigner" do
        expect { described_class.verify!(valid_request) }.to raise_error(UniKey::UntrustedSigner)
      end
    end
  end

  describe ".verify" do
    context "with valid signature" do
      it "returns verified request info" do
        result = described_class.verify(valid_request)

        expect(result).not_to be_nil
        expect(result.signer).to eq(signer_domain)
      end
    end

    context "with invalid signature" do
      it "returns nil" do
        request = valid_request.dup
        request[:headers]["X-UniKey-Signature"] = Base64.strict_encode64("invalid" * 8)

        expect(described_class.verify(request)).to be_nil
      end
    end
  end
end
