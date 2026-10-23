package tools

import (
	"strings"
	"testing"
)

func TestRedactCredentialsFromResearchContextKeepsAuthorizedScope(t *testing.T) {
	input := `Assessment scope: https://app.example.test and https://api.example.test:8443.
The assessment uses these test accounts:
- alice@example.test / Alice-Secret-17!
- bob@example.test / Bob-Secret-29!
Inspect common API documentation such as /docs and /openapi.json. Prior observation: GET /health returned 200.`

	got := RedactCredentialsFromResearchContext(input)
	for _, secret := range []string{"Alice-Secret-17!", "Bob-Secret-29!", "alice@example.test", "bob@example.test"} {
		if strings.Contains(got, secret) {
			t.Errorf("research context exposed credential %q", secret)
		}
	}
	if count := strings.Count(got, "[REDACTED ACCOUNT]"); count != 2 {
		t.Errorf("redacted %d accounts, want 2", count)
	}
	for _, evidence := range []string{
		"https://app.example.test",
		"https://api.example.test:8443",
		"/docs",
		"/openapi.json",
		"GET /health returned 200",
	} {
		if !strings.Contains(got, evidence) {
			t.Errorf("research context lost safe evidence %q", evidence)
		}
	}
}

func TestRedactCredentialsFromResearchContextPreservesURLAfterCredentialHeading(t *testing.T) {
	const input = "Credentials:\nhttps://app.example.test/docs\n"
	if got := RedactCredentialsFromResearchContext(input); got != input {
		t.Fatalf("redacted authorized URL following credential heading: %q", got)
	}
}

func TestRedactCredentialsFromResearchContextPreservesBulletedURLAfterCredentialHeading(t *testing.T) {
	const input = "Credentials:\n- https://app.example.test/docs\n"
	if got := RedactCredentialsFromResearchContext(input); got != input {
		t.Fatalf("redacted bulleted authorized URL following credential heading: %q", got)
	}
}

func TestRedactCredentialsFromResearchContextPreservesBareTargetAfterCredentialHeading(t *testing.T) {
	const input = "Credentials:\n- app.example.test/docs\n"
	if got := RedactCredentialsFromResearchContext(input); got != input {
		t.Fatalf("redacted bare authorized target following credential heading: %q", got)
	}
}

func TestRedactCredentialsFromResearchContextPreservesInlineURLAfterCredentialHeading(t *testing.T) {
	const input = "Credentials: https://app.example.test/docs"
	if got := RedactCredentialsFromResearchContext(input); got != input {
		t.Fatalf("redacted inline authorized URL following credential heading: %q", got)
	}
}

func TestRedactCredentialsFromResearchContextLeavesCredentialFreeTaskUnchanged(t *testing.T) {
	const input = `Research public documentation for https://docs.example.test and the authorized API at https://api.example.test/v2. No API docs lead is known.`
	if got := RedactCredentialsFromResearchContext(input); got != input {
		t.Fatalf("credential-free context changed: got %q", got)
	}
}

func TestRedactCredentialsFromResearchContextMasksColonSeparatedAccounts(t *testing.T) {
	input := `Credentials:
- alice@example.test: Alice-Secret-17!
- bob: Bob-Secret-29!
Authorized targets: https://app.example.test and https://api.example.test.`
	got := RedactCredentialsFromResearchContext(input)
	for _, secret := range []string{"alice@example.test", "Alice-Secret-17!", "bob", "Bob-Secret-29!"} {
		if strings.Contains(got, secret) {
			t.Errorf("research context exposed credential %q", secret)
		}
	}
	if !strings.Contains(got, "https://app.example.test") || !strings.Contains(got, "https://api.example.test") {
		t.Fatalf("research context lost target scope: %q", got)
	}
}

func TestRedactCredentialsFromResearchContextMasksUnbulletedEmailAccount(t *testing.T) {
	input := `Credentials:
alice@example.test: Alice-Secret-17!
bob: Bob-Secret-29!
Scope: https://api.example.test/docs`
	got := RedactCredentialsFromResearchContext(input)
	for _, secret := range []string{"alice@example.test", "Alice-Secret-17!", "bob", "Bob-Secret-29!"} {
		if strings.Contains(got, secret) {
			t.Errorf("research context exposed credential %q", secret)
		}
	}
	if !strings.Contains(got, "Scope: https://api.example.test/docs") {
		t.Fatalf("research context lost scope: %q", got)
	}
}

func TestRedactCredentialsFromResearchContextMasksPrefixedSecretAssignments(t *testing.T) {
	input := "OPENAI_API_KEY=sk-live-placeholder\nclient_secret=oauth-live-placeholder\n"
	got := RedactCredentialsFromResearchContext(input)
	for _, secret := range []string{"sk-live-placeholder", "oauth-live-placeholder"} {
		if strings.Contains(got, secret) {
			t.Errorf("research context exposed secret assignment value %q", secret)
		}
	}
}

func TestRedactCredentialsFromResearchContextMasksWhitespaceSeparatedAccountFields(t *testing.T) {
	input := `Disposable test accounts:
- Alice: username alice, password Alpha-Secret-71!
- Bob: username bob, password Beta-Secret-82!`
	got := RedactCredentialsFromResearchContext(input)
	for _, secret := range []string{"username alice", "username bob", "Alpha-Secret-71!", "Beta-Secret-82!"} {
		if strings.Contains(got, secret) {
			t.Errorf("research context exposed credential %q: %q", secret, got)
		}
	}
}
