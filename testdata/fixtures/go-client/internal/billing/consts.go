package billing

import "net/http"

// A constant declared in a different file of the same package still has to
// resolve, which is what the group pass exists for.
const auditBase = "https://audit.acme.example.com/api"

func PostAudit() {
	http.Post(auditBase+"/v2/events", "application/json", nil)
}
