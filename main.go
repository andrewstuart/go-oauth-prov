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
	h.HandleFunc("/token", handleToken)
	h.HandleFunc("/validate", handleValidate)

	err := http.ListenAndServe(":8080", &CORSMux{h})
	if err != nil {
		log.Fatal(err)
	}
}
