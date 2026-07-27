package html

import (
	"html/template"
	"log/slog"
	"net/http"
)

// The popup lands on the eBay redirect domain, so it can't share state with the
// app directly. It reports the outcome to the opener via postMessage, targeted
// at the frontend origin. The payload is structured (and includes the seller
// username on success / the reason on failure) so the page can react precisely
// instead of guessing from whether the window closed.
//
// Values are interpolated by html/template, which escapes them for the
// surrounding <script> context — payload renders as a JS object literal.

const callbackTmpl = `<!DOCTYPE html>
<html>
<head><title>{{.Title}}</title></head>
<body>
	<h1>{{.Heading}}</h1>
	<p>{{.Detail}}</p>
	<script>
		var payload = {{.Payload}};
		if (window.opener) {
			window.opener.postMessage(payload, {{.Origin}});
			setTimeout(function () { window.close(); }, 300);
		} else {
			document.body.innerHTML += "<p>You can close this window.</p>";
		}
	</script>
</body>
</html>`

func renderCallback(w http.ResponseWriter, title, heading, detail string, payload map[string]string, frontendURL string) {
	t, err := template.New("callback").Parse(callbackTmpl)
	if err != nil {
		slog.Error("backend: template error", "err", err)
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	if err := t.Execute(w, struct {
		Title   string
		Heading string
		Detail  string
		Payload map[string]string
		Origin  string
	}{title, heading, detail, payload, frontendURL}); err != nil {
		slog.Error("backend: template execution error", "err", err)
	}
}

// RenderAuthSuccess reports a completed authorization, naming the seller that
// was linked so the opener can confirm it even when re-authorizing an existing
// seller (where no new account appears in the list).
func RenderAuthSuccess(w http.ResponseWriter, frontendURL string, ebayUser string) {
	renderCallback(w,
		"Authorization Complete",
		"Seller Authorized",
		"You can close this window.",
		map[string]string{"type": "seller_authorized", "user": ebayUser},
		frontendURL,
	)
}

// RenderAuthError reports a failed authorization along with the reason.
func RenderAuthError(w http.ResponseWriter, errorMsg string, frontendURL string) {
	renderCallback(w,
		"Authorization Failed",
		"Authorization Failed",
		errorMsg,
		map[string]string{"type": "seller_authorization_failed", "error": errorMsg},
		frontendURL,
	)
}
