package main

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/gob"
	"encoding/xml"
	"log"
	"net/http"

	"github.com/RangelReale/osin"
	"github.com/andrewstuart/gosaml2"
)

var cert tls.Certificate

func init() {
	var err error
	cert, err = tls.LoadX509KeyPair("../openid-sp-enc.crt", "../openid-sp-enc.key")
	if err != nil {
		log.Fatal(err)
	}

	gob.Register(&saml.Assertion{})
}

func handleSAML(w http.ResponseWriter, r *http.Request) {
	resp := server.NewResponse()
	defer resp.Close()

	defer func() {
		err := osin.OutputJSON(resp, w, r)
		if err != nil {
			log.Println("error finishing authZ request", err)
		}
	}()

	if ar := server.HandleAuthorizeRequest(resp, r); ar != nil {
		defer server.FinishAuthorizeRequest(resp, r, ar)

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

		var a saml.Assertion
		err = xml.NewDecoder(bytes.NewBuffer(pt)).Decode(&a)

		if err != nil {
			log.Println(err)
			w.WriteHeader(500)
			return
		}

		ar.UserData = a.Attributes
		ar.Authorized = true

		//Write json and xml for testing
		// io.Copy(w, bytes.NewBuffer(pt))
	}
}
