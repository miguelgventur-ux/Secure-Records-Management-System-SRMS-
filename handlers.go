package main

import (
	"net/http"
	"strconv"
	"strings"
)

// =============================================================================
// CSRF VALIDATION HELPER
// =============================================================================

// requireCSRF checks the CSRF token submitted in a form against the session's
// stored token.  All state-changing (POST) requests must pass this check.
func requireCSRF(w http.ResponseWriter, r *http.Request, session *Session) bool {
	if r.FormValue("csrf_token") != session.CSRFToken {
		http.Error(w, "Invalid or missing CSRF token — request rejected.", http.StatusForbidden)
		return false
	}
	return true
}

// =============================================================================
// TEMPLATE DATA HELPERS
// =============================================================================

// pageData bundles the common values available in every template.
func pageData(user *User, session *Session, extra map[string]interface{}) map[string]interface{} {
	d := map[string]interface{}{
		"User":      user,
		"CSRFToken": session.CSRFToken,
	}
	for k, v := range extra {
		d[k] = v
	}
	return d
}

// extractRecordID parses the numeric record ID from paths of the form
// /admin/record/42 or /admin/record/42/update.
func extractRecordID(path string) (int, bool) {
	// Strip the leading /admin/record/ prefix then take the first path segment.
	trimmed := strings.TrimPrefix(path, "/admin/record/")
	parts := strings.SplitN(trimmed, "/", 2)
	if len(parts) == 0 || parts[0] == "" {
		return 0, false
	}
	id, err := strconv.Atoi(parts[0])
	if err != nil || id < 1 {
		return 0, false
	}
	return id, true
}
