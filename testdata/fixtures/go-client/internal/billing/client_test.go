package billing

import (
	"net/http"
	"testing"
)

// Test code legitimately talks to fake hosts. Indexing it would misrepresent
// what production depends on.
func TestSomething(t *testing.T) {
	http.Get("https://api.test-only.example.com/never/indexed")
}
