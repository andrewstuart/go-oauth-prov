package main

import (
	"log"
	"net/http"
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
	h := http.NewServeMux()
	h.HandleFunc("/authorize", handleAuthorize)
	// h.HandleFunc("/uPortal/saml/SSO", handleSAML)
	h.HandleFunc("/token", handleToken)
	h.HandleFunc("/validate", handleValidate)

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Println(r)
		w.Write([]byte(`<html><head><title>HEY</title></head><body><h1>HEY</h1></html>`))
		return
	})

	go func() {
		err := http.ListenAndServe(":8080", &CORSMux{h})
		if err != nil {
			log.Fatal(err)
		}
	}()

	err := http.ListenAndServeTLS(":8081", "../cert", "../key", &CORSMux{h})
	if err != nil {
		log.Fatal(err)
	}
}
