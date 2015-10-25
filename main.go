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
		w.WriteHeader(200)
		w.Write(nil)
		return
	}
	cm.sm.ServeHTTP(w, r)
}

func main() {
	h := http.NewServeMux()
	h.HandleFunc("/authorize", handleAuthorize)
	h.HandleFunc("/token", handleToken)
	h.HandleFunc("/saml", handleSAML)
	h.HandleFunc("/validate", handleValidate)

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Println(r)
		w.Write([]byte(`<html><head><title>HEY</title></head><body><h1>HEY</h1></html>`))
		return
	})

	m := &CORSMux{h}

	go func() {
		err := http.ListenAndServe("127.0.0.4:8080", m)
		if err != nil {
			log.Fatal(err)
		}
	}()

	// go func() {
	// 	err := http.ListenAndServeTLS("127.0.0.4:8443", "../*.us-west-2.elb.amazonaws.com.crt", "../*.us-west-2.elb.amazonaws.com.key", m)
	// 	if err != nil {
	// 		log.Fatal(err)
	// 	}
	// }()

	err := http.ListenAndServeTLS("127.0.0.4:8443", "../*.astuart.co.crt", "../*.astuart.co.key", m)
	if err != nil {
		log.Fatal(err)
	}
}
