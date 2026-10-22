// Package pidl_test checks the AAuth PIDL document in this directory and
// the walkthrough generated from it.
package pidl_test

import (
	"bytes"
	"os"
	"reflect"
	"testing"

	"github.com/grokify/pidl"
	"github.com/grokify/pidl/analyze"
	"github.com/grokify/pidl/render"
)

const (
	document    = "aauth_protocol.json"
	walkthrough = "../../docs/aauth/explorer/aauth.walkthrough.json"
)

func protocol(t *testing.T) *pidl.Protocol {
	t.Helper()
	p, err := pidl.ParseFile(document)
	if err != nil {
		t.Fatal(err)
	}
	if errs := p.Validate(); len(errs) > 0 {
		t.Fatalf("%s does not validate: %v", document, errs)
	}
	return p
}

// TestAAuthProtocol pins the document's scenarios and the one finding it
// is meant to show: in federated access the PS signs the request to the
// AS, while the resource token it presents was delivered to the agent.
func TestAAuthProtocol(t *testing.T) {
	p := protocol(t)
	if got := p.ScenarioIDs(false); !reflect.DeepEqual(got, []string{
		"agent-identity", "resource-managed", "person-identity", "ps-authorization", "federated-authorization",
	}) {
		t.Errorf("main scenarios = %v", got)
	}
	if got := len(p.ScenarioIDs(true)) - len(p.ScenarioIDs(false)); got != 3 {
		t.Errorf("fragments = %d, want 3", got)
	}

	opts := analyze.DefaultAnalysisOptions()
	opts.MinSeverity = analyze.SeverityInfo
	var signer []string
	for _, r := range analyze.Analyze(p, opts).Risks {
		switch r.ID {
		case "SEC019":
			signer = append(signer, r.Location)
		case "SEC017", "SEC018", "SEC020", "SEC021":
			t.Errorf("unexpected %s at %s: %s", r.ID, r.Location, r.Description)
		}
	}
	if !reflect.DeepEqual(signer, []string{"scenarios[4].flows[6] (federated-authorization)"}) {
		t.Errorf("SEC019 = %v, want the PS to AS request in federated access", signer)
	}
}

// TestWalkthroughIsCurrent fails when the AAuth Explorer's walkthrough no
// longer matches the document.
func TestWalkthroughIsCurrent(t *testing.T) {
	want, err := render.NewWalkthroughJSON().RenderString(protocol(t))
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(walkthrough)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(bytes.TrimSpace(got), bytes.TrimSpace([]byte(want))) {
		t.Fatalf("%s is out of date; run docs/aauth/explorer/build.sh and commit it", walkthrough)
	}
}
