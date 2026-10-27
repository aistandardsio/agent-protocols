---
title: AAuth Explorer
hide:
  - navigation
  - toc
---

# AAuth Explorer

Step through each AAuth access mode one message at a time: the sequence diagram highlights the roles and the message, and the panels beside it show the request and response as HTTP or as a `curl` command, with each token decoded. Pick a scenario at the top; use → and ← (click the viewer first), or the buttons under the diagram.

The walkthrough is generated from [`aauth/pidl/aauth_protocol.json`](https://github.com/aistandardsio/agent-protocols/blob/main/aauth/pidl/aauth_protocol.json), which follows `draft-hardt-oauth-aauth-protocol-11`.

To see your own deployment's messages beside these steps, see [Comparing an AAuth Run with the Protocol](../../guides/aauth-observed-runs.md).

<style>
  .md-main__inner.md-grid, .md-content { max-width: none; }
  #aauth-walkthrough { height: 85vh; min-height: 640px; }
</style>

<div id="aauth-walkthrough"></div>
<script src="https://cdn.jsdelivr.net/npm/@grokify/pidl-viewer@0.9.0/dist-lib/pidl-viewer.js"
        integrity="sha384-LdxcShWogEyPfyA6wBOBDm2XohJP8NahS9JI3SFxjRn5+8aMbml8NxLwjwPQqH6a"
        crossorigin="anonymous"
        data-pidl-target="#aauth-walkthrough"
        data-pidl-src="aauth.walkthrough.json"></script>

## Regenerating

```bash
docs/aauth/explorer/build.sh
```

The script validates the PIDL document and writes `aauth.walkthrough.json` beside this page. It needs [pidl](https://github.com/grokify/pidl) v0.9.0 or later. The viewer is [`@grokify/pidl-viewer`](https://www.npmjs.com/package/@grokify/pidl-viewer), loaded from jsDelivr at a fixed version and checked against its hash.
