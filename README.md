# UniKey Ruby Gem

DKIM-based signature verification for AI agent requests.

## Installation

Add to your Gemfile:

```ruby
gem 'unikey'
```

Then run:

```bash
bundle install
```

## Usage

### Rails Controller

```ruby
class Api::AgentController < ApplicationController
  include UniKey::Rails::ControllerHelper
  before_action :verify_unikey_signature

  def balance
    # @verified_request.agent_email is the authenticated agent
    render json: { balance: current_campaign.total }
  end

  def donate
    # agent_email helper method is also available
    donation = create_donation(agent_email, params[:amount])
    render json: { success: true, donation_id: donation.id }
  end
end
```

### Manual Verification

```ruby
# Returns verified info or raises UniKey::Error
result = UniKey.verify!(request)
puts result.agent_email  # => "user@gmail.com"
puts result.signer       # => "unikey.tech"
puts result.timestamp    # => 2024-01-01 12:00:00 UTC

# Returns nil instead of raising
result = UniKey.verify(request)
```

### Configuration

```ruby
# config/initializers/unikey.rb
UniKey.configure do |config|
  # How long to cache DNS lookups (default: 1 hour)
  config.dns_cache_ttl = 3600

  # Maximum age of requests in seconds (default: 5 minutes)
  config.max_request_age = 300

  # Optional: restrict to specific signer domains
  config.trusted_signers = ["unikey.tech"]
end
```

## How It Works

1. AI agents authenticate via UniKey server using DKIM-verified email
2. UniKey signs outgoing requests with Ed25519
3. Your service verifies signatures by looking up the public key from DNS
4. No shared secrets - public keys are published at `unikey._domainkey.{domain}`

## Headers

UniKey adds these headers to requests:

| Header | Description |
|--------|-------------|
| `X-UniKey-Signature` | Base64-encoded Ed25519 signature |
| `X-UniKey-Signer` | Domain that signed the request |
| `X-UniKey-Timestamp` | Unix timestamp (prevents replay) |
| `X-UniKey-Body-Hash` | SHA-256 hash of request body |
| `X-Agent-Email` | The authenticated agent's email |

## DNS Record

UniKey publishes public keys as DNS TXT records:

```
unikey._domainkey.unikey.tech  TXT  "v=DKIM1; k=ed25519; p=BASE64_PUBLIC_KEY"
```

## License

MIT
