# UniKey Ruby

Signature verification for Ruby and Rails. Verify [Trust Packets](https://unikey.tech) and signed HTTP requests from AI agents using Ed25519 + DNS-published public keys.

**UniKey is a Universal Trust Primitive for AI Agents** — it lets any service verify that a request genuinely came from a specific agent, without shared secrets, API keys, or passwords. Public keys live in DNS (the same infrastructure that secures email via DKIM), so verification is fully decentralized.

This gem is the **verifier side**. Install it in your service to verify incoming Trust Packets from agents. Works with any language on the sender side (the companion [unikey-tp](https://github.com/anthropics/unikey-python) Python library, or any Ed25519 implementation).

## Installation

```ruby
gem 'unikey'
```

**Requirements:** Ruby >= 3.0 | **Dependencies:** `ed25519`

## Quick Start

### 1. Verify a Trust Packet

When an agent sends your service a Trust Packet (via email, HTTP POST, or any transport), verify it in one call:

```ruby
require "unikey"

# packet_data is a Hash parsed from the incoming JSON
result = UniKey.verify_packet!(packet_data)

result.valid       # => true
result.subject     # => "isaiah.baca@gmail.com"  (who sent it)
result.action      # => "login"                  (what they want)
result.params      # => { "session_duration" => 3600 }
result.signer      # => "gmail.com"              (domain that signed it)
result.callback_url # => "https://device/cb/123" (where to send the response)
```

Behind the scenes, the gem:
1. Validates the packet structure and expiration
2. Looks up the signer's Ed25519 public key from DNS (`unikey._domainkey.gmail.com`)
3. Verifies the signature over the canonicalized packet
4. Returns the verified claims

No API keys. No shared secrets. Just DNS + cryptography.

### 2. Process the Request and Respond

```ruby
# Verify
result = UniKey.verify_packet!(packet_data)

# Do whatever the agent asked
case result.action
when "login"
  session = create_session(result.subject)
  response_params = { login_url: session_url(session), message: "Welcome!" }
when "purchase_item"
  order = create_order(result.subject, result.params)
  response_params = { order_id: order.id, total: order.total }
end

# Build a signed response Trust Packet back to the agent
response = UniKey.build_packet(
  subject: "service@yourapp.com",
  audience: result.subject,
  action: "#{result.action}_response",
  params: response_params,
  signing_key: your_ed25519_key,
  signer_domain: "yourapp.com",
)

# POST the response to the agent's callback URL
Net::HTTP.post(URI(result.callback_url), response.to_json, "Content-Type" => "application/json")
```

### 3. Rails Controller Integration

```ruby
class Api::AgentController < ApplicationController
  include UniKey::Rails::ControllerHelper

  # Verifies X-UniKey-* headers on every request
  before_action :verify_unikey_signature

  def balance
    # @verified_request is set automatically
    render json: { balance: 100, agent: agent_email }
  end

  def donate
    donation = create_donation(agent_email, params[:amount])
    render json: { success: true, donation_id: donation.id }
  end
end
```

The helper sets `@verified_request` on success or returns a structured 401 JSON error on failure. Use `verify_unikey_signature_optional` if you want verification without blocking.

## What Is a Trust Packet?

A Trust Packet is a self-contained, cryptographically signed JSON container. It bundles identity, intent, and proof into one structure:

```json
{
  "header": {
    "version": "1.0",
    "packet_type": "action_request",
    "packet_id": "pkt_abc123",
    "timestamp": 1736784000,
    "expires": 1736784300
  },
  "claims": {
    "subject": "isaiah.baca@gmail.com",
    "issuer": "gmail.com",
    "audience": "login@yourapp.com",
    "scope": ["auth:login"],
    "delegation_chain": []
  },
  "payload": {
    "action": "login",
    "params": { "callback_url": "https://device/cb/123", "session_duration": 3600 },
    "message": "Please log me into my account."
  },
  "signatures": [{
    "algorithm": "ed25519",
    "signer": "gmail.com",
    "key_selector": "unikey",
    "signature": "<base64 Ed25519 signature>",
    "signed_at": 1736784000
  }]
}
```

**Transport-agnostic.** Trust Packets can travel over email (SMTP + DKIM), HTTPS POST, WebSocket, or any channel. The signature makes them self-verifying regardless of how they arrive.

## Configuration

```ruby
# config/initializers/unikey.rb
UniKey.configure do |config|
  # How long to cache DNS lookups (default: 3600s / 1 hour)
  config.dns_cache_ttl = 3600

  # Reject packets/requests older than this (default: 300s / 5 minutes)
  config.max_request_age = 300

  # Restrict to specific signer domains (nil = trust any valid signer)
  config.trusted_signers = ["gmail.com", "unikey.tech"]

  # RFC-002: DNS hardening with multi-resolver consensus
  config.dns_hardening_enabled = true
  config.dns_resolvers = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]
  config.dns_min_consistent = 2  # at least 2 of 3 resolvers must agree

  # Logging (optional)
  config.logger = Rails.logger
end
```

## Trust Packet API

### Building

```ruby
packet = UniKey::TrustPacket.build(
  subject: "agent@example.com",       # who is making the request
  audience: "service@target.com",     # who should receive it
  action: "do_something",             # what action to perform
  signing_key: ed25519_signing_key,   # Ed25519::SigningKey
  signer_domain: "example.com",       # domain publishing the public key in DNS
  scope: ["read", "write"],           # permissions (default: ["*"])
  params: { key: "value" },           # action parameters (optional)
  message: "Human-readable note",     # optional message
  ttl: 300,                           # seconds until expiration (default: 300)
)

packet.to_h                           # full packet as Hash
packet.to_json                        # JSON string
packet.canonical_form                 # deterministic JSON (for debugging)
packet.expired?                       # true if TTL has passed
```

### Verification

```ruby
# Raises on failure: InvalidSignature, InvalidPacket, ExpiredRequest, etc.
result = UniKey.verify_packet!(packet_data)

# Returns nil on failure (no exception)
result = UniKey.verify_packet(packet_data)
```

The result object:

| Field | Description |
|-------|-------------|
| `result.valid` | Always true (exception raised otherwise) |
| `result.packet_id` | Unique packet ID |
| `result.packet_type` | `"action_request"` or `"action_response"` |
| `result.subject` | Who made the request (email) |
| `result.issuer` | Domain that vouches for the subject |
| `result.audience` | Intended recipient |
| `result.scope` | Permission array |
| `result.action` | Requested action name |
| `result.params` | Action parameters hash |
| `result.message` | Human-readable message |
| `result.callback_url` | Extracted from params (if present) |
| `result.signer` | Domain that signed the packet |
| `result.timestamp` | Time the packet was created |
| `result.expires_at` | Time the packet expires (or nil) |
| `result.delegation_chain` | Delegation chain (if delegated) |

### Parsing (without verification)

```ruby
packet = UniKey.parse_packet(hash_or_json_string)
packet.header.packet_id
packet.claims.subject
packet.payload.action
```

## HTTP Request Verification

For the header-based signature flow (DKIM-over-HTTPS), the agent signs each HTTP request directly:

### Expected Headers

| Header | Description |
|--------|-------------|
| `X-UniKey-Signature` | Base64 Ed25519 signature |
| `X-UniKey-Signer` | Domain that signed the request |
| `X-UniKey-Timestamp` | Unix timestamp (replay prevention) |
| `X-UniKey-Body-Hash` | Base64 SHA-256 of request body |
| `X-Agent-Email` | The agent's verified email |

### Canonical String (What Gets Signed)

```
POST
https://example.com/api/action
<sha256-body-hash>
1736784000
agent@example.com
```

### Manual Verification

```ruby
result = UniKey.verify!(request)
result.agent_email  # => "user@gmail.com"
result.signer       # => "unikey.tech"
result.timestamp    # => Time object

# Non-raising variant
result = UniKey.verify(request)
```

Works with `ActionDispatch::Request`, `Rack::Request`, or a plain Hash:

```ruby
request = {
  headers: {
    "X-UniKey-Signature" => "...",
    "X-UniKey-Signer" => "unikey.tech",
    "X-UniKey-Timestamp" => "1736784000",
    "X-UniKey-Body-Hash" => "...",
    "X-Agent-Email" => "user@gmail.com",
  },
  body: '{"action":"purchase"}',
  method: "POST",
  url: "https://example.com/api/purchase",
}

result = UniKey.verify!(request)
```

## DNS Hardening (RFC-002)

Standard DNS queries trust a single resolver. DNS hardening queries multiple independent resolvers and requires consensus. If resolvers disagree on the public key, verification fails closed — protecting against DNS poisoning.

```ruby
UniKey.configure do |config|
  config.dns_hardening_enabled = true
  config.dns_resolvers = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]
  config.dns_min_consistent = 2
end
```

Default resolvers: Google (`8.8.8.8`), Cloudflare (`1.1.1.1`), Quad9 (`9.9.9.9`).

## DNS Record Setup

Publish your Ed25519 public key as a DNS TXT record:

```
unikey._domainkey.example.com  TXT  "v=DKIM1; k=ed25519; p=<base64 public key>"
```

This is the same format used by DKIM email signatures. The `unikey` selector distinguishes it from email DKIM records.

## Error Handling

All errors inherit from `UniKey::Error`:

| Error | Meaning |
|-------|---------|
| `InvalidSignature` | Ed25519 signature verification failed |
| `ExpiredRequest` | Packet/request is older than `max_request_age` |
| `InvalidPacket` | Trust Packet structure is malformed |
| `MissingHeaders` | Required HTTP headers absent |
| `DNSLookupFailed` | Public key not found in DNS |
| `UntrustedSigner` | Signer not in `trusted_signers` whitelist |
| `DNSInconsistency` | Hardened DNS: resolvers disagree (fail-closed) |

## How It Works

```
Agent (sender)                      Your Service (verifier)
  |                                    |
  |  1. Build Trust Packet             |
  |  2. Sign with Ed25519 private key  |
  |  3. Send (email / HTTPS / any)  -->|
  |                                    |  4. Validate structure & expiration
  |                                    |  5. Canonicalize to deterministic JSON
  |                                    |  6. Look up public key from DNS:
  |                                    |     unikey._domainkey.{signer}
  |                                    |  7. Verify Ed25519 signature
  |                                    |  8. Process the action
  |                                    |
  |  9. Signed response <--------------| (optional: response Trust Packet)
```

No shared secrets. No API keys. The public key lives in DNS — the same infrastructure that already secures billions of emails daily via DKIM.

## Running Tests

```bash
bundle install
bundle exec rspec   # 38 specs
```

## License

MIT
