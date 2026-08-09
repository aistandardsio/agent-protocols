// Command mcp-ema demonstrates MCP Enterprise-Managed Authorization end to
// end using ID-JAG (draft-ietf-oauth-identity-assertion-authz-grant):
//
//	IdP AS (issuer, :18081)          Resource AS (receiver)              mcp-google (resource server)
//	  token-exchange → ID-JAG    jwt-bearer → access token (JWT)     Bearer JWT → tools, scope-gated
//
// Two receiver modes:
//
//   - Default (offline): the in-process reference idjag.AuthorizationServer
//     on :18082 exchanges the ID-JAG.
//   - Keycloak interop: set KEYCLOAK_URL (e.g. http://localhost:8081, started
//     with --features=identity-assertion-jwt); the demo bootstraps a realm as
//     receiver via the keycloak adapter and exchanges the ID-JAG there.
//
// Start mcp-google first (offline mode shown; see README.md):
//
//	mcp-google serve --http :8080 \
//	  --idjag-issuer http://localhost:18082 \
//	  --credentials service-account.json
//
// Then run the demo:
//
//	go run ./examples/mcp-ema
//
// EXPERIMENTAL: implements an IETF draft and (in Keycloak mode) an
// experimental Keycloak feature; both are subject to change.
package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/aistandardsio/agent-protocols/adapters/keycloak"
	"github.com/aistandardsio/agent-protocols/idjag"
)

const (
	idpAddr    = "localhost:18081"
	idpIssuer  = "http://localhost:18081"
	rsAddr     = "localhost:18082"
	rsIssuer   = "http://localhost:18082"
	keyID      = "mcp-ema-demo-key"
	agentID    = "agent:report-writer"
	userID     = "user:alice"
	demoClient = "mcp-google"
	demoSecret = "demo-secret"
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("demo failed: %v", err)
	}
}

func run() error {
	ctx := context.Background()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("generating key: %w", err)
	}
	jwks := &idjag.JWKS{Keys: []idjag.JWK{
		idjag.NewJWKFromRSAPublicKey(&privateKey.PublicKey, keyID, idjag.AlgorithmRS256),
	}}

	// === Enterprise IdP (ID-JAG issuer) on :18081 ===
	idpServer := idjag.NewIdPAuthorizationServer(idpIssuer, jwt.SigningMethodRS256, privateKey, keyID)
	idpServer.AssertionTTL = 5 * time.Minute
	idpServer.DelegationPolicy = func(_ context.Context, req *idjag.IDJAGRequest) error {
		log.Printf("   [IdP] delegation policy: user authorized client %q", req.ClientID)
		return nil
	}

	idpMux := http.NewServeMux()
	idpMux.HandleFunc("GET /.well-known/jwks.json", idjag.NewJWKSHandler(jwks).ServeHTTP)
	idpMux.HandleFunc("POST /token", idpServer.ServeHTTP)
	startServer(idpAddr, idpMux)

	keycloakURL := os.Getenv("KEYCLOAK_URL")
	var exchangeIDJAG func(ctx context.Context, assertion, scope string) (string, error)
	var receiverIssuer string

	if keycloakURL == "" {
		// === Reference resource AS (receiver) on :18082 ===
		receiverIssuer = rsIssuer
		verifier := idjag.NewStaticKeyVerifier(&privateKey.PublicKey, keyID, idjag.VerifierOptions{
			ExpectedIssuer:   idpIssuer,
			ExpectedAudience: rsIssuer,
		})
		resourceAS := idjag.NewAuthorizationServer(verifier, jwt.SigningMethodRS256, privateKey, keyID, rsIssuer)
		rsMux := http.NewServeMux()
		rsMux.HandleFunc("GET /.well-known/jwks.json", idjag.NewJWKSHandler(jwks).ServeHTTP)
		rsMux.HandleFunc("POST /token", resourceAS.ServeHTTP)
		startServer(rsAddr, rsMux)

		bearerClient := idjag.NewJWTBearerClient(rsIssuer + "/token")
		exchangeIDJAG = func(ctx context.Context, assertion, scope string) (string, error) {
			resp, err := bearerClient.Exchange(ctx, assertion, scope)
			if err != nil {
				return "", err
			}
			return resp.AccessToken, nil
		}
		log.Printf("Receiver: reference idjag.AuthorizationServer at %s (offline mode)", rsIssuer)
	} else {
		// === Keycloak receiver (interop mode) ===
		realm := envOr("KEYCLOAK_REALM", "agents")
		receiverIssuer = keycloak.RealmIssuer(keycloakURL, realm)

		admin := keycloak.NewAdminClient(keycloakURL,
			envOr("KEYCLOAK_ADMIN", "admin"), envOr("KEYCLOAK_ADMIN_PASSWORD", "admin"))
		err := admin.BootstrapReceiver(ctx, realm,
			keycloak.ExternalIssuer{
				Alias:     "mcp-ema-idp",
				IssuerURL: idpIssuer,
				JWKSURL:   idpIssuer + "/.well-known/jwks.json",
			},
			keycloak.ReceiverClient{ClientID: demoClient, ClientSecret: demoSecret},
		)
		if err != nil {
			return fmt.Errorf("bootstrapping Keycloak receiver: %w", err)
		}

		exchanger, err := keycloak.NewExchanger(ctx, keycloakURL, realm, demoClient, demoSecret)
		if err != nil {
			return fmt.Errorf("creating Keycloak exchanger: %w", err)
		}
		exchangeIDJAG = func(ctx context.Context, assertion, scope string) (string, error) {
			resp, err := exchanger.Exchange(ctx, assertion, scope)
			if err != nil {
				return "", err
			}
			return resp.AccessToken, nil
		}
		//nolint:gosec // G706: realm/URL are operator-supplied env config, not untrusted input
		log.Printf("Receiver: Keycloak realm %q at %s (interop mode)", realm, keycloakURL)
	}

	// === Step 0: user authenticates at the IdP (simulated OIDC ID token) ===
	log.Println("\n0. User authenticates at enterprise IdP (simulated ID token)")
	idToken, err := mockUserIDToken(privateKey)
	if err != nil {
		return err
	}

	// === Step 1: agent obtains ID-JAG via RFC 8693 token exchange ===
	log.Println("\n1. Agent → IdP: token-exchange, requested_token_type=id-jag")
	idpClient := idjag.NewIDJAGClient(idpIssuer + "/token")
	idjagResp, err := idpClient.RequestIDJAG(ctx, &idjag.IDJAGRequest{
		SubjectToken:     idToken,
		SubjectTokenType: idjag.TokenTypeIDToken,
		Audience:         receiverIssuer,
		ClientID:         agentID,
		Scope:            "docs:read",
	})
	if err != nil {
		return fmt.Errorf("requesting ID-JAG: %w", err)
	}
	assertion, err := idjag.ParseAssertion(idjagResp.AccessToken)
	if err != nil {
		return fmt.Errorf("parsing ID-JAG: %w", err)
	}
	log.Printf("   ID-JAG issued: sub=%s client_id=%s", assertion.Subject, assertion.ClientID)

	// === Step 2: exchange ID-JAG for an access token (RFC 7523) ===
	log.Println("\n2. Agent → Receiver: jwt-bearer, assertion=ID-JAG")
	accessToken, err := exchangeIDJAG(ctx, idjagResp.AccessToken, "docs:read")
	if err != nil {
		return fmt.Errorf("exchanging ID-JAG: %w", err)
	}
	log.Printf("   Access token issued (%d bytes)", len(accessToken))

	// === Step 3: call mcp-google with the access token ===
	mcpURL := envOr("MCP_URL", "http://localhost:8080/mcp")
	log.Printf("\n3. Agent → mcp-google (%s): MCP over HTTP with Bearer token", mcpURL)
	return callMCPGoogle(ctx, mcpURL, accessToken)
}

// callMCPGoogle connects to mcp-google over streamable HTTP, lists tools,
// and demonstrates scope gating: the token carries docs:read only, so a
// sheets tool call must be denied while docs access proceeds.
func callMCPGoogle(ctx context.Context, mcpURL, accessToken string) error {
	client := mcp.NewClient(&mcp.Implementation{Name: "mcp-ema-demo", Version: "0.1.0"}, nil)
	session, err := client.Connect(ctx, &mcp.StreamableClientTransport{
		Endpoint:   mcpURL,
		HTTPClient: &http.Client{Transport: &bearerTransport{token: accessToken}},
	}, nil)
	if err != nil {
		return fmt.Errorf("connecting to mcp-google (is it running? see README): %w", err)
	}
	defer func() {
		if err := session.Close(); err != nil {
			log.Printf("closing MCP session: %v", err)
		}
	}()

	tools, err := session.ListTools(ctx, nil)
	if err != nil {
		return fmt.Errorf("listing tools: %w", err)
	}
	log.Printf("   Authenticated: %d tools visible", len(tools.Tools))

	log.Println("\n4. Scope gating: token has docs:read only")
	_, err = session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "get_sheet_values",
		Arguments: map[string]any{"spreadsheet_id": "demo", "range": "A1"},
	})
	if err != nil {
		log.Printf("   sheets tool DENIED as expected: %v", err)
	} else {
		return fmt.Errorf("expected sheets tool to be denied for docs:read-scoped token")
	}

	result, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "get_document_metadata",
		Arguments: map[string]any{"document_id": "demo-document-id"},
	})
	if err != nil {
		return fmt.Errorf("docs tool call rejected by authorization layer: %w", err)
	}
	// The Google API call itself may fail with demo credentials; what
	// matters here is that authorization admitted the scoped call.
	log.Printf("   docs tool ADMITTED by authorization (isError=%v — Google API result depends on credentials)", result.IsError)

	log.Println("\nDemo completed: ID-JAG issued, exchanged, and enforced end to end.")
	return nil
}

// bearerTransport injects the access token into every MCP HTTP request.
type bearerTransport struct {
	token string
}

func (t *bearerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("Authorization", "Bearer "+t.token)
	return http.DefaultTransport.RoundTrip(req)
}

// mockUserIDToken simulates the OIDC ID token a user receives after
// authenticating at the enterprise IdP.
func mockUserIDToken(privateKey *rsa.PrivateKey) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"iss": idpIssuer,
		"sub": userID,
		"aud": agentID,
		"iat": jwt.NewNumericDate(now),
		"exp": jwt.NewNumericDate(now.Add(10 * time.Minute)),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = keyID
	return token.SignedString(privateKey)
}

func startServer(addr string, handler http.Handler) {
	server := &http.Server{Addr: addr, Handler: handler, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		if err := server.ListenAndServe(); err != http.ErrServerClosed {
			log.Fatalf("server %s error: %v", addr, err)
		}
	}()
	time.Sleep(100 * time.Millisecond)
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
