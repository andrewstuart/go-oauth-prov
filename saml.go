package main

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"io"
	"log"
	"net/http"

	"github.com/andrewstuart/gosaml2"
)

var cert tls.Certificate

func init() {
	var err error
	cert, err = tls.LoadX509KeyPair("../openid-sp-enc.crt", "../openid-sp-enc.key")
	if err != nil {
		log.Fatal(err)
	}
}

func handleSAML(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		log.Println(err)
	}

	sr := r.Form.Get("SAMLResponse")
	bs, err := base64.StdEncoding.DecodeString(sr)
	if err != nil {
		log.Println("Error decoding base64", err)
	}

	var res saml.Response
	err = xml.NewDecoder(bytes.NewBuffer(bs)).Decode(&res)
	if err != nil {
		log.Println(err)
		return
	}

	pt, err := res.Decrypt(cert)
	if err != nil {
		log.Println(err)
		return
	}
	log.Println(string(pt), err)

	var a saml.Assertion
	err = xml.NewDecoder(bytes.NewBuffer(pt)).Decode(&a)

	if err != nil {
		log.Println(err)
		w.WriteHeader(500)
		return
	}

	//Write json and xml for testing
	json.NewEncoder(w).Encode(a)
	io.Copy(w, bytes.NewBuffer(pt))
}
