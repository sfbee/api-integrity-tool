package y

import "net/http"

// A dependency's own API calls are not ours to monitor.
func Fetch() {
	http.Get("https://api.vendored-dependency.example.com/v1/thing")
}
