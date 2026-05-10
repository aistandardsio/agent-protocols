# AAuth Simple Example: Identity-Only Flow

This example demonstrates the **identity-only flow** where agents present their cryptographic identity directly to resources without requiring an auth token from a Person Server.

## When to Use

Identity-only mode is suitable when:

- Resources only need to verify the agent's identity
- No fine-grained authorization is needed
- Resources trust any authenticated agent from known providers

## How It Works

1. **Agent creates signed request**: The agent signs the HTTP request using RFC 9421 HTTP Message Signatures
2. **Resource verifies identity**: The resource fetches the agent's public key from the Agent Provider's JWKS and verifies the signature
3. **Access granted**: If the signature is valid, the resource grants access

## Key Components

- `Agent`: Signs HTTP requests with its private key
- `ResourceServer`: Verifies signatures using Agent Provider's JWKS
- `Signature-Key` header: Contains the agent's identity token (aa-agent+jwt)
- `Signature` header: Contains the HTTP message signature

## Running the Example

```bash
go run ./aauth/examples/simple
```

## Expected Output

```
Created agent: aauth:calendar-bot@example.com
Created resource server: https://calendar.example.com
Resource server running at: http://127.0.0.1:XXXXX

Sending signed request to resource...
  URL: http://127.0.0.1:XXXXX/events
  Signature-Key header present: true
  Signature header present: true

Response status: 200
Response: map[agent_id:aauth:calendar-bot@example.com key_id:... message:Hello from the resource!]

Identity-only flow completed successfully!
```

## Related

- [Resource-Managed Example](../resource-managed/README.md) - When resources require auth tokens
- [Delegation Example](../delegation/README.md) - Human-to-agent delegation
