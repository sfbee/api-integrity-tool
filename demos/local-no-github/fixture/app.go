// Command storefront is a stand-in for a service that settles payments through
// the AcmePay vendor. Only the outbound calls matter here: the demo scans this
// file and replays two versions of the vendor specification against it.
package main

import (
	"net/http"
	"strings"
)

const vendor = "https://api.acmepay.io"

func main() {
	// The fixture is scanned, never executed; the vendor host does not resolve.
}

// chargeBasket takes payment for a completed basket. Storefront prices
// everything in one currency, so the query string is fixed.
func chargeBasket(payload string) (*http.Response, error) {
	return http.Post(vendor+"/v1/charges?currency=usd", "application/json", strings.NewReader(payload))
}

// merchantBalance reads the settled balance for the seller dashboard.
func merchantBalance() (*http.Response, error) {
	return http.Get(vendor + "/v1/balance")
}

// chargeStatus polls a single charge while an order is still pending.
func chargeStatus(id string) (*http.Response, error) {
	return http.Get(vendor + "/v1/charges/" + id)
}

// customerProfile is the demo's control case: no upstream change should ever
// attribute a finding to it.
func customerProfile(id string) (*http.Response, error) {
	return http.Get(vendor + "/v1/customers/" + id)
}

// listRefunds backs the returns queue. The vendor has never published this
// path, which is what makes it show up as undocumented.
func listRefunds() (*http.Response, error) {
	return http.Get(vendor + "/v1/refunds")
}

// updateCustomer writes a profile edit back to the vendor. The method is passed
// as http.MethodPut rather than a literal, so the scanner records the call with
// method ANY -- a known limit, kept here deliberately.
func updateCustomer(id, payload string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodPut, vendor+"/v1/customers/"+id, strings.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	return http.DefaultClient.Do(req)
}
