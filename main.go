package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/RangelReale/osin"
)

//CORSMux handles cors
type CORSMux struct {
	sm http.Handler
}

//ServeHTTP serves http
func (cm *CORSMux) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type,Authorization")
	w.Header().Set("Access-Control-Allow-Methods", "GET,POST")

	if r.Method == "OPTIONS" {
		w.Write(nil)
		return
	}
	cm.sm.ServeHTTP(w, r)
}

func main() {
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
	}

	ts := NewRedisStore()
	server := osin.NewServer(sc, ts)

	h := http.NewServeMux()

	h.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		resp := server.NewResponse()
		defer resp.Close()
		defer osin.OutputJSON(resp, w, r)

		if ar := server.HandleAuthorizeRequest(resp, r); ar != nil {
			if valid, err := validateUser(r.Form.Get("username"), r.Form.Get("password")); err == nil && valid {
				ar.Authorized = true
			}

			server.FinishAuthorizeRequest(resp, r, ar)
		}

		if resp.IsError && resp.InternalError != nil {
			fmt.Printf("resp.InternalError = %+v\n", resp.InternalError)
		}

	})

	h.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
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
			// resp.Output["reason"] = "Client has not authenticated itself."
			fmt.Printf("resp.ErrorId = %+v\n", resp.ErrorId)

			fmt.Printf("resp.InternalError = %+v\n", resp.InternalError)
		}

		osin.OutputJSON(resp, w, r)
	})

	h.HandleFunc("/validate", func(w http.ResponseWriter, r *http.Request) {
		t := r.URL.Query().Get("token")
		scope := r.URL.Query().Get("scope")

		if t == "" {
			w.WriteHeader(404)
			return
		}

		access, err := ts.LoadAccess(t)
		if err != nil {
			w.WriteHeader(404)
			return
		}

		if access == nil {
			w.WriteHeader(404)
			return
		}

		scopes := strings.Split(scope, " ")
		for i := range scopes {
			if match, err := filepath.Match(scopes[i], scope); scopes[i] == "everything" || err == nil && match {
				json.NewEncoder(w).Encode(struct {
					Scope    string
					UserData interface{}
				}{access.Scope, access.UserData})
				return
			}
		}

		w.WriteHeader(404)
	})

	err := http.ListenAndServe(":8080", &CORSMux{h})
	if err != nil {
		log.Fatal(err)
	}
}
