package main

import (
	"fmt"

	"github.com/RangelReale/osin"
)

//TestStorage stores things
type TestStorage struct {
	access    map[string]*osin.AccessData
	authorize map[string]*osin.AuthorizeData
	clients   map[string]osin.Client
}

//NewTestStorage gives a TestStorage
func NewTestStorage() *TestStorage {
	return &TestStorage{
		access:    make(map[string]*osin.AccessData),
		authorize: make(map[string]*osin.AuthorizeData),
		clients:   make(map[string]osin.Client),
	}
}

//Close closes a session
func (ts *TestStorage) Close() {
}

//Clone clones the current storage
func (ts *TestStorage) Clone() osin.Storage {
	return ts
	// ns := NewTestStorage()
	// for aKey := range ts.access {
	// 	ns.access[aKey] = ts.access[aKey]
	// }
	// for aKey := range ts.authorize {
	// 	ns.authorize[aKey] = ts.authorize[aKey]
	// }
	// for cKey := range ts.clients {
	// 	ns.clients[cKey] = ts.clients[cKey]
	// }
	// return ns
}

//GetClient gets a client by id
func (ts *TestStorage) GetClient(id string) (osin.Client, error) {
	if cli, ok := ts.clients[id]; ok {
		return cli, nil
	}
	return &osin.DefaultClient{
		Id:          "1",
		Secret:      "thing",
		RedirectUri: "http://localhost:9000/token",
	}, nil
	// return nil, fmt.Errorf("Client does not exist")
}

//SaveAuthorize saves authorization
func (ts *TestStorage) SaveAuthorize(ad *osin.AuthorizeData) error {
	fmt.Printf("save authorize ad = %+v\n", ad)
	ts.authorize[ad.Code] = ad
	fmt.Printf("ts.authorize = %+v\n", ts.authorize)
	return nil
}

//LoadAuthorize loads authorization data by id.
func (ts *TestStorage) LoadAuthorize(code string) (*osin.AuthorizeData, error) {
	fmt.Printf("loading auth for code code = %+v\n", code)
	if ad, ok := ts.authorize[code]; ok {
		return ad, nil
	}
	fmt.Printf("ts.authorize = %+v\n", ts.authorize)
	return nil, fmt.Errorf("TestStorage could not load authorization for code %s", code)
}

//RemoveAuthorize removes authorization data
func (ts *TestStorage) RemoveAuthorize(code string) error {
	delete(ts.authorize, code)
	return nil
}

//SaveAccess saves access data
func (ts *TestStorage) SaveAccess(ad *osin.AccessData) error {
	fmt.Printf("save access ad = %+v\n", ad)
	ts.access[ad.AccessToken] = ad
	fmt.Printf("ts.access = %+v\n", ts.access)
	return nil
}

//LoadAccess gets access data.
func (ts *TestStorage) LoadAccess(token string) (*osin.AccessData, error) {
	if ad, ok := ts.access[token]; ok {
		fmt.Printf("ad = %+v\n", ad)
		return ad, nil
	}
	return nil, fmt.Errorf("Could not find data for token %s", token)
}

//RemoveAccess removes access data.
func (ts *TestStorage) RemoveAccess(token string) error {
	delete(ts.access, token)
	return nil
}

//LoadRefresh gets a refresh token.
func (ts *TestStorage) LoadRefresh(token string) (*osin.AccessData, error) {
	if ad, ok := ts.access[token]; ok {
		return ad, nil
	}
	return nil, fmt.Errorf("Refresh data for token %s not found.", token)
}

//RemoveRefresh removes a refresh token from storage.
func (ts *TestStorage) RemoveRefresh(token string) error {
	if ad, ok := ts.access[token]; ok {
		ad.RefreshToken = ""
	}
	return nil
}
