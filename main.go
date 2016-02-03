package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
)

var certDir string

func init() {
	certDir = os.Getenv("CERT_DIR")
	if certDir == "" {
		certDir = "/certs"
	}
}

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
	h.HandleFunc("/token_info", handleTokenInfo)

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Println(r)
		w.Write([]byte(`<html><head><title>HEY</title></head><body><h1>HEY</h1></html>`))
		return
	})

	m := &CORSMux{h}

	go func() {
		err := http.ListenAndServe(":8080", m)
		if err != nil {
			log.Fatal(err)
		}
	}()

	name := os.Getenv("HTTP_CERT_NAME")

	err := http.ListenAndServeTLS(":8443", crt(name), key(name), m)
	if err != nil {
		log.Fatal("Error serving tls", err)
	}
}

func key(s string) string {
	return fmt.Sprintf("%s/%s.key", certDir, s)
}

func crt(s string) string {
	return fmt.Sprintf("%s/%s.crt", certDir, s)
}
