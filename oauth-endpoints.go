package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/RangelReale/osin"
)

var server *osin.Server
var ts *RedisStore

func init() {
	sc := osin.NewServerConfig()
	sc.AllowedAuthorizeTypes = osin.AllowedAuthorizeType{
		osin.CODE,
		osin.TOKEN,
	}

	sc.AllowedAccessTypes = osin.AllowedAccessType{
		osin.AUTHORIZATION_CODE,
		osin.REFRESH_TOKEN,
		osin.ASSERTION,
		osin.PASSWORD,
		osin.AccessRequestType("saml2-grant"),
	}

	ts = NewRedisStore()
	server = osin.NewServer(sc, ts)
}

func handleToken(w http.ResponseWriter, r *http.Request) {
	resp := server.NewResponse()
	defer resp.Close()

	if ar := server.HandleAccessRequest(resp, r); ar != nil {
		if u, p, ok := r.BasicAuth(); ok && u == ar.Client.GetId() && p == ar.Client.GetSecret() {
			ar.Authorized = true
		}

		server.FinishAccessRequest(resp, r, ar)
	}

	if resp.IsError {
		resp.StatusCode = 401
	}

	osin.OutputJSON(resp, w, r)
}

func handleAuthorize(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()

	if err != nil {
		log.Println("error parsing form", err)
	}

	fmt.Printf("r.Form = %+v\n", r.Form)

	validSess := checkSession(r)

	if !validSess && (r.Form.Get("username") == "" || r.Form.Get("password") == "") {
		writeAuthForm(w, r)
		return
	}

	resp := server.NewResponse()

	defer func() {
		if resp.IsError && resp.InternalError != nil {
			fmt.Printf("resp.InternalError = %+v\n", resp.InternalError)
		}
	}()

	defer resp.Close()
	defer osin.OutputJSON(resp, w, r)

	log.Println(r)

	if ar := server.HandleAuthorizeRequest(resp, r); ar != nil {
		defer server.FinishAuthorizeRequest(resp, r, ar)

		if validSess {
			log.Println("authed by session")
			ar.Authorized = true
			return
		}

		valid, err := validateUser(userPass{r.Form.Get("username"), r.Form.Get("password")})

		if err == errExceededAttempts {
			resp.StatusCode = 420
			resp.Output["reason"] = "Authorization attempts exceeded"
		}

		if valid {
			ar.Authorized = true
			writeSession(w, r.Form.Get("username"))
		}
	}
}

func handleValidate(w http.ResponseWriter, r *http.Request) {
	t := r.URL.Query().Get("token")
	scope := r.URL.Query().Get("scope")

	if t == "" {
		w.WriteHeader(400)
		fmt.Fprintf(w, "No token provided")
		return
	}

	access, err := ts.LoadAccess(t)
	if err != nil {
		log.Println(err)
		w.WriteHeader(404)
		return
	}

	if access == nil {
		w.WriteHeader(404)
		return
	}

	if access.IsExpired() {
		w.WriteHeader(401)
		w.Write([]byte("Token has expired"))
		return
	}

	scopes := strings.Split(access.Scope, " ")
	for i := range scopes {
		if match, err := filepath.Match(scopes[i], scope); err == nil && match {
			json.NewEncoder(w).Encode(struct {
				Scope    string
				UserData interface{}
			}{access.Scope, access.UserData})
			return
		}
	}

	w.WriteHeader(404)
}

func handleTokenInfo(w http.ResponseWriter, r *http.Request) {
	t := r.URL.Query().Get("token")

	access, err := ts.LoadAccess(t)
	if err != nil {
		log.Println(err)
		w.WriteHeader(500)
		return
	}

	if access.UserData != nil {
		err := json.NewEncoder(w).Encode(access.UserData)
		if err != nil {
			log.Println(err)
		}
	}
}

func writeAuthForm(w http.ResponseWriter, r *http.Request) {
	t, err := template.New("auth").Parse(`
	<html>
	<head><title>Auth</title></head>
	<body>
	<form method="POST" action="{{.ActionURL}}">
	<input name="username" />
	<input type="password" name="password" />
	<button action="submit">Go</button>
	</form>
	</body>
	</html>`)

	if err != nil {
		log.Println(err)
		w.WriteHeader(500)
		return
	}

	f := "/authorize?" + r.URL.RawQuery

	err = t.Execute(w, struct{ ActionURL string }{f})
	if err != nil {
		log.Println(err)
	}
}
