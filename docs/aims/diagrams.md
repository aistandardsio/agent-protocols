# Protocol Diagrams

These sequence diagrams are generated from [PIDL](https://github.com/grokify/pidl) protocol definitions.

## WIT Issuance Flow

The Workload Identity Token (WIT) issuance flow shows how an AI agent workload obtains a WIT credential through SPIRE workload attestation.

```mermaid
sequenceDiagram
    autonumber

    participant agent as AI Agent Workload
    participant spire_agent as SPIRE Agent
    participant spire_server as SPIRE Server
    participant attestor as Node/Workload Attestor

    rect rgb(240, 240, 240)
    note right of agent: Workload Attestation
    agent->>spire_agent: FetchJWTSVID (audience, SPIFFE ID)
    spire_agent->>attestor: Attest Workload (PID, UID, K8s SA, etc.)
    attestor->>attestor: Gather Attestation Evidence
    attestor-->>spire_agent: Attestation Result + Selectors
    end

    rect rgb(240, 240, 240)
    note right of agent: WIT Issuance
    spire_agent->>spire_server: FetchSVID Request (workload selectors)
    spire_server->>spire_server: Match Registration Entry
    spire_server->>spire_server: Create WIT (iss, sub=SPIFFE ID, aud, exp, cnf)
    spire_server->>spire_server: Sign with Trust Domain Key
    spire_server-->>spire_agent: JWT-SVID (WIT)
    spire_agent-->>agent: Workload Identity Token
    end
```

**PIDL Source:** [`aims_wit_flow.json`](https://github.com/grokify/agent-protocols/blob/main/aims/pidl/aims_wit_flow.json)

---

## WPT Authentication Flow

The WIMSE Proof Token (WPT) authentication flow shows how an agent uses its WIT and a request-bound WPT to authenticate to a target service.

```mermaid
sequenceDiagram
    autonumber

    participant agent as AI Agent
    participant target_service as Target Service
    participant trust_bundle as SPIFFE Trust Bundle

    rect rgb(240, 240, 240)
    note right of agent: Proof Token Creation
    agent->>agent: Create WPT (iss=SPIFFE ID, aud, htm, htu, nonce)
    agent->>agent: Sign WPT with Agent Key
    end

    rect rgb(240, 240, 240)
    note right of agent: Request Submission
    agent->>target_service: POST /api/action (Authorization: Bearer WIT, Workload-Identity-Token: WPT)
    end

    rect rgb(240, 240, 240)
    note right of agent: Verification
    target_service->>trust_bundle: GET /trust-bundle (Trust Domain Keys)
    trust_bundle-->>target_service: Trust Bundle (JWKS)
    target_service->>target_service: Verify WIT Signature + Validate Claims
    target_service->>target_service: Extract cnf Claim (Proof Key)
    target_service->>target_service: Verify WPT Signature with cnf Key
    target_service->>target_service: Validate Request Binding (htm, htu, nonce)
    target_service->>target_service: Check Replay (jti, nonce, iat)
    target_service->>target_service: Authorize Based on SPIFFE ID
    target_service-->>agent: 200 OK (Response Data)
    end
```

**PIDL Source:** [`aims_wpt_flow.json`](https://github.com/grokify/agent-protocols/blob/main/aims/pidl/aims_wpt_flow.json)

---

## mTLS Authentication Flow

For X.509 SVID-based authentication, agents use mutual TLS directly without separate proof tokens.

```mermaid
sequenceDiagram
    autonumber

    participant agent as AI Agent
    participant spire_agent as SPIRE Agent
    participant target_service as Target Service
    participant trust_bundle as SPIFFE Trust Bundle

    rect rgb(240, 240, 240)
    note right of agent: X.509 SVID Retrieval
    agent->>spire_agent: FetchX509SVID Request
    spire_agent->>spire_agent: Attest Workload
    spire_agent-->>agent: X.509 SVID (cert + private key)
    end

    rect rgb(240, 240, 240)
    note right of agent: mTLS Handshake
    agent->>target_service: TLS ClientHello
    target_service->>agent: TLS ServerHello + Certificate
    agent->>target_service: Client Certificate (X.509 SVID)
    target_service->>trust_bundle: Fetch Trust Bundle
    trust_bundle-->>target_service: CA Certificates
    target_service->>target_service: Verify Client Certificate Chain
    target_service->>target_service: Extract SPIFFE ID from SAN
    target_service-->>agent: TLS Handshake Complete
    end

    rect rgb(240, 240, 240)
    note right of agent: Authorized Request
    agent->>target_service: HTTPS Request (mTLS session)
    target_service->>target_service: Authorize Based on SPIFFE ID
    target_service-->>agent: 200 OK (Response Data)
    end
```

---

## Combined Flow: WIT + WPT End-to-End

This diagram shows the complete flow from workload attestation through authenticated API access.

```mermaid
sequenceDiagram
    autonumber

    participant agent as AI Agent
    participant spire_agent as SPIRE Agent
    participant spire_server as SPIRE Server
    participant target_service as Target Service

    rect rgb(240, 240, 240)
    note right of agent: 1. Obtain WIT
    agent->>spire_agent: FetchJWTSVID(audience)
    spire_agent->>spire_agent: Attest Workload
    spire_agent->>spire_server: FetchSVID(selectors)
    spire_server->>spire_server: Create & Sign WIT
    spire_server-->>spire_agent: JWT-SVID (WIT)
    spire_agent-->>agent: WIT with cnf binding
    end

    rect rgb(240, 240, 240)
    note right of agent: 2. Create WPT & Request
    agent->>agent: Create WPT(htm=POST, htu=/api/data)
    agent->>agent: Sign WPT with bound key
    agent->>target_service: POST /api/data<br/>Authorization: Bearer {WIT}<br/>Workload-Identity-Token: {WPT}
    end

    rect rgb(240, 240, 240)
    note right of agent: 3. Verify & Respond
    target_service->>target_service: Verify WIT signature
    target_service->>target_service: Extract cnf key from WIT
    target_service->>target_service: Verify WPT with cnf key
    target_service->>target_service: Validate htm/htu match request
    target_service->>target_service: Authorize by SPIFFE ID
    target_service-->>agent: 200 OK (data)
    end
```

---

## About PIDL

These diagrams are generated from [PIDL](https://github.com/grokify/pidl) (Protocol Interaction Description Language) definitions. PIDL provides:

- **Single source of truth** - JSON protocol definitions
- **Multiple output formats** - Mermaid, PlantUML, Graphviz DOT, D2
- **Validation** - Schema-based validation of protocol definitions
- **Consistency** - Same structure for all protocols

### Regenerating Diagrams

```bash
# Install PIDL CLI
go install github.com/grokify/pidl/cmd/pidl@latest

# Generate Mermaid diagrams
pidl generate -f mermaid aims/pidl/aims_wit_flow.json
pidl generate -f mermaid aims/pidl/aims_wpt_flow.json
```
