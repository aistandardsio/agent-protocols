# Comparing an AAuth Run with the Protocol

The [AAuth Explorer](../aauth/explorer/index.md) explains each AAuth access mode with example messages written to teach it. When you build an agent, a resource or a server, you also want to see what your own deployment sent: which steps it performed, which it skipped, which tokens it carried and what it exchanged between the steps. [PIDL](https://github.com/grokify/pidl) v0.10.0 can put a real run beside the walkthrough, step by step, from the same AAuth document.

## What You Get

A page with each scenario the run performed added after the scenario it is an instance of. Its **Concept / Observed** switch shows either the document's example or the message your system sent, in the same panels:

- each step's request and response, with the time and the gap from the step before;
- the step's status: matched (strong or weak), not seen, skipped, or not observable, such as the person approving in a browser;
- each AAuth token the message carried, decoded but not verified;
- the exchanges the protocol does not describe, such as metadata and key fetches, drawn between the steps they followed.

Raw tokens, signatures and credentials are masked by default; decoded claims are kept.

## Try It Against the Sandbox

The [aauth-postman](https://github.com/aistandardsio/aauth-postman) repository runs the AAuth Petstore flow against the [aauth-go](https://github.com/aauth-dev/aauth-go) sandbox, captures the sandbox's trace of every message and writes the page:

```bash
make demo   # writes demo/live.html; open it in a browser
```

The run is found as two scenario instances, agent identity (browsing the pets) and PS authorization challenged on the API call (placing an order), with every step matched strongly and every token identified by its type. See the aauth-postman README for the checkouts and ports it needs.

## With Your Own Deployment

You need three files:

| File | Where it comes from |
|------|---------------------|
| The AAuth document | [`aauth/pidl/aauth_protocol.json`](https://github.com/aistandardsio/agent-protocols/blob/main/aauth/pidl/aauth_protocol.json) in this repository |
| An observation (`pidl-observation/v1`) | your capture, converted with `pidl observe import` |
| A binding (`pidl-binding/v1`) | written once for your deployment |

```bash
pidl observe import --from sandbox -o run.json trace.json
pidl generate -f viewer --observation run.json --binding deployment.json \
  -o live.html aauth/pidl/aauth_protocol.json
```

The binding maps your deployment to the document's roles (`agent`, `ap`, `ps`, `as`, `resource`) by the capturing tool's labels and by host, and gives your resource's real paths for its steps. You do not need to map `person`: it is a user role, so pidl treats its steps as unobservable, since a server's capture cannot see the browser. The aauth-postman repository's `bindings/sandbox-petstore.binding.json` is a complete example. See pidl's [Observed Runs guide](https://grokify.github.io/pidl/guides/observed-runs/) for the formats and the matching rules.

## What the Document Says for Matching

The AAuth document carries the facts matching needs, so a binding only describes a deployment:

- **Where each token travels.** Each token definition has `carried_in`. Agent, person and auth tokens travel in the `jwt` parameter of `Signature-Key` or in a JSON body field; the resource token in the `resource-token` parameter of `AAuth-Requirement` or the `resource_token` field. Since several tokens share `Signature-Key`, each place names the JWT `typ` (`aa-agent+jwt`, `aa-person+jwt`, `aa-auth+jwt`, `aa-resource+jwt`, `jkt-s256+jwt`) that tells them apart.
- **How the polls are recognized.** The consent and resource-managed polls match `GET /pending/{id}` and repeat, so every poll in a run belongs to the one step, which shows the answer that ended it.

Every other step is matched by its example's method, path and status. Tests with pidl v0.10.0 validate both.
