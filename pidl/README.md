# ID-JAG Protocol Definitions (PIDL)

This directory contains [PIDL](https://github.com/grokify/pidl) definitions for ID-JAG flows.

## Files

| File | Description |
|------|-------------|
| `idjag_simple.json` | Agent-only authentication (no human delegation) |
| `idjag_delegation.json` | Human-to-agent delegation with actor claim |

## Generated Diagrams

Diagrams are generated using the `pidl` CLI tool:

| Format | Simple Flow | Delegation Flow |
|--------|-------------|-----------------|
| PlantUML | `idjag_simple.puml` | `idjag_delegation.puml` |
| Mermaid | `idjag_simple.mmd` | `idjag_delegation.mmd` |
| Graphviz DOT | `idjag_simple.dot` | `idjag_delegation.dot` |

## Regenerating Diagrams

Install the PIDL CLI:

```bash
go install github.com/grokify/pidl/cmd/pidl@latest
```

Validate definitions:

```bash
pidl validate pidl/*.json
```

Generate all formats:

```bash
# PlantUML
pidl generate -f plantuml -o pidl/idjag_simple.puml pidl/idjag_simple.json
pidl generate -f plantuml -o pidl/idjag_delegation.puml pidl/idjag_delegation.json

# Mermaid
pidl generate -f mermaid -o pidl/idjag_simple.mmd pidl/idjag_simple.json
pidl generate -f mermaid -o pidl/idjag_delegation.mmd pidl/idjag_delegation.json

# Graphviz DOT
pidl generate -f dot -o pidl/idjag_simple.dot pidl/idjag_simple.json
pidl generate -f dot -o pidl/idjag_delegation.dot pidl/idjag_delegation.json
```

## Rendering to Images

### PlantUML to SVG/PNG

```bash
# Using PlantUML jar
java -jar plantuml.jar -tsvg pidl/idjag_simple.puml

# Using PlantUML server
curl -X POST --data-binary @pidl/idjag_simple.puml https://www.plantuml.com/plantuml/svg/
```

### Mermaid to SVG/PNG

```bash
# Using mermaid-cli (mmdc)
npx @mermaid-js/mermaid-cli -i pidl/idjag_simple.mmd -o pidl/idjag_simple.svg
```

### Graphviz DOT to SVG/PNG

```bash
dot -Tsvg pidl/idjag_simple.dot -o pidl/idjag_simple_flow.svg
dot -Tpng pidl/idjag_delegation.dot -o pidl/idjag_delegation_flow.png
```

## Protocol Structure

### Simple Flow (Agent-Only)

```
Agent → Assertion Issuer → Authorization Server → Resource Server
```

The agent authenticates as itself without human delegation:

- **Subject (`sub`)**: Agent's identity (e.g., `agent:calendar-bot`)
- **No actor claim**: Agent is both subject and actor

### Delegation Flow (Human-to-Agent)

```
Human → Identity Provider → Agent → Authorization Server → Resource Server
```

The agent acts on behalf of a human user:

- **Subject (`sub`)**: Human user's identity (e.g., `user:alice`)
- **Actor (`act`)**: Agent's identity (e.g., `agent:calendar-bot`)

Both identities are preserved through the token exchange, enabling:

- Authorization based on human permissions
- Audit trails showing both who authorized and who acted
- Agent-specific policies and restrictions
