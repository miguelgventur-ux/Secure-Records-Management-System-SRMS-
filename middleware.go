package main

import "net/http"

// =============================================================================
// ADDITIONAL SECURITY FEATURE 1 – SECURITY RESPONSE HEADERS
//
// A middleware that applies defensive HTTP headers to every response:
//   - Content-Security-Policy:  restricts resource origins to prevent XSS
//   - X-Frame-Options:          prevents clickjacking via iframes
//   - X-Content-Type-Options:   prevents MIME-sniffing attacks
//   - Referrer-Policy:          limits referrer information leakage
// =============================================================================

func securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'none'; object-src 'none'")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		next.ServeHTTP(w, r)
	})
}
