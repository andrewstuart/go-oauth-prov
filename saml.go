package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"log"
	"net/http"
)

type bst string

var recvKey *rsa.PrivateKey
var recvCert *x509.Certificate

// func init() {
// 	bs, err := ioutil.ReadFile("./dev.portal.cccedplan.org.key")
// 	if err != nil {
// 		log.Fatal(err)
// 	}

// 	recvKey, err = x509.ParsePKCS1PrivateKey(bs)
// 	if err != nil {
// 		log.Fatal(err)
// 	}
// }

func (b bst) bytes() []byte {
	bs, _ := base64.StdEncoding.DecodeString(string(b))
	return bs
}

func (b bst) String() string {
	return string(b)
}

type keyInfo struct {
	// EncryptionMethod string `xml:"EncryptionMethod>Algorithm"`
	X509Data    bst `xml:"KeyInfo>X509Data>X509Certificate"`
	CipherValue bst `xml:"CipherData>CipherValue"`
}

type samlResponse struct {
	XMLName     xml.Name
	Destination string  `xml:"Destination,attr"`
	Issuer      string  `xml:"Issuer"`
	Value       string  `xml:",attr"`
	Key         keyInfo `xml:"EncryptedAssertion>EncryptedData>KeyInfo>EncryptedKey"`
	Data        bst     `xml:"EncryptedAssertion>EncryptedData>CipherData>CipherValue"`
}

func (sr *samlResponse) getCert() (*x509.Certificate, error) {
	bs := sr.Key.X509Data.bytes()
	return x509.ParseCertificate(bs)
}

func (sr *samlResponse) getData() ([]byte, error) {
	return base64.StdEncoding.DecodeString(sr.Data.String())
}

func (sr *samlResponse) Decrypt() ([]byte, error) {
	log.Println(sr.Data.bytes())
	return recvKey.Decrypt(rand.Reader, sr.Key.CipherValue.bytes(), nil)
}

func handleSAML(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		log.Println(err)
	}

	saml := r.Form.Get("SAMLResponse")
	bs, err := base64.StdEncoding.DecodeString(saml)
	if err != nil {
		log.Println("Error decoding base64", err)
	}

	var res samlResponse
	err = xml.NewDecoder(bytes.NewBuffer(bs)).Decode(&res)
	if err != nil {
		log.Println(err)
		return
	}

	pt, err := res.Decrypt()
	log.Println(pt, err)
}
