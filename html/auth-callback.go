package html

import (
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
)

// https://developer.mozilla.org/en-US/docs/Web/API/MessageEvent
// HTML’s JavaScript executes in the browser (as such, client-side),
// sending a postMessage to the parent window (window.opener)
// with the "seller_authorized" message.
// The window.opener.postMessage call is a client-side operation.
// It communicates between two browser windows
// (the popup/child window and its parent/opener window)
// using the HTML5 postMessage API.

func RenderAuthSuccess(w http.ResponseWriter, frontendURL string) {
	tmpl := `
<!DOCTYPE html>
<html>
<head>
	<title>Authorization Complete</title>
</head>
<body>
	<h1>Seller Authorized</h1>
	<script>
		console.log("backend: sending postMessage");
		if (window.opener) {
			window.opener.postMessage("seller_authorized", "%s");
			setTimeout(() => {
				console.log("backend: closing window");
				window.close();
			}, 500);
		} else {
			console.log("backend: no opener");
			document.body.innerHTML += "<p>Please close this window.</p>";
		}
	</script>
</body>
</html>
`
	t, err := template.New("success").Parse(fmt.Sprintf(tmpl, frontendURL))
	if err != nil {
		slog.Error("backend: template error", "err", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	if err := t.Execute(w, nil); err != nil {
		slog.Error("backend: template execution error", "err", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func RenderAuthError(w http.ResponseWriter, errorMsg string, frontendURL string) {
	tmpl := `
<!DOCTYPE html>
<html>
<head>
	<title>Authorization Failed</title>
</head>
<body>
	<h1>Authorization Failed</h1>
	<script>
		console.log("backend: sending error postMessage");
		if (window.opener) {
			window.opener.postMessage({ error: "{{.Error}}" }, "%s");
			setTimeout(() => {
				console.log("backend: closing window");
				window.close();
			}, 500);
		} else {
			console.log("backend: no opener");
			document.body.innerHTML += "<p>Please close this window.</p>";
		}
	</script>
</body>
</html>
`
	t, err := template.New("error").Parse(fmt.Sprintf(tmpl, frontendURL))
	if err != nil {
		slog.Error("backend: template error", "err", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	if err := t.Execute(w, struct{ Error string }{Error: errorMsg}); err != nil {
		slog.Error("backend: template error", "err", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}
