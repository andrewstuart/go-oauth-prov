package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/RangelReale/osin"
)

//User is a user
type User struct {
	Stuff string
}

//CORSMux handles cors
type CORSMux struct {
	sm http.Handler
}

//ServeHTTP serves http
func (cm *CORSMux) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
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

	ts := NewTestStorage()
	server := osin.NewServer(sc, ts)

	h := http.NewServeMux()

	h.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		resp := server.NewResponse()
		defer resp.Close()

		if ar := server.HandleAuthorizeRequest(resp, r); ar != nil {
			if r.URL.Query().Get("user") == "andrew" && r.URL.Query().Get("password") == "pass" {
				ar.Authorized = true
			}

			ar.UserData = User{"Hey"}
			server.FinishAuthorizeRequest(resp, r, ar)
		}

		if resp.IsError && resp.InternalError != nil {
			fmt.Printf("resp.InternalError = %+v\n", resp.InternalError)
		}

		resp.Output["foo"] = "bar"

		osin.OutputJSON(resp, w, r)
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
			fmt.Printf("resp.InternalError = %+v\n", resp.InternalError)
		}

		osin.OutputJSON(resp, w, r)
	})

	err := http.ListenAndServe(":8080", &CORSMux{h})
	if err != nil {
		log.Fatal(err)
	}
}
