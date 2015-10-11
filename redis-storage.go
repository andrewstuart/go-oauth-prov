package main

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"log"

	"github.com/RangelReale/osin"
)

//RedisStore stores oauth stuff in redis.
type RedisStore struct {
	access    map[string]*osin.AccessData
	authorize map[string]*osin.AuthorizeData
	clients   map[string]osin.Client
}

//NewRedisStore returns RedisStore
func NewRedisStore() *RedisStore {
	return &RedisStore{
		access:    make(map[string]*osin.AccessData),
		authorize: make(map[string]*osin.AuthorizeData),
		clients:   make(map[string]osin.Client),
	}
}

func init() {
	gob.Register(osin.DefaultClient{})
}

//Close closes a session
func (rs *RedisStore) Close() {
}

//Clone clones the current storage
func (rs *RedisStore) Clone() osin.Storage {
	return rs
}

//GetClient gets a client by id
func (rs *RedisStore) GetClient(id string) (osin.Client, error) {
	if cli, ok := rs.clients[id]; ok {
		return cli, nil
	}
	return &osin.DefaultClient{
		Id:          "1",
		Secret:      "thing",
		RedirectUri: "http://localhost:9000/login",
	}, nil
	// return nil, fmt.Errorf("Client does not exist")
}

//SaveAuthorize saves authorization
func (rs *RedisStore) SaveAuthorize(ad *osin.AuthorizeData) error {
	fmt.Printf("save authorize ad = %+v\n", ad)
	rs.authorize[ad.Code] = ad
	fmt.Printf("ts.authorize = %+v\n", rs.authorize)

	b := &bytes.Buffer{}
	err := gob.NewEncoder(b).Encode(ad)
	if err != nil {
		return fmt.Errorf("error encoding gob: %v", err)
	}
	_, err = rds.Do("SET", fmt.Sprintf("oauth:authorize:%s", ad.Code), b.Bytes())
	if err != nil {
		log.Println("REDIS error", err)
	}

	return nil
}

//LoadAuthorize loads authorization data by id.
func (rs *RedisStore) LoadAuthorize(code string) (*osin.AuthorizeData, error) {
	fmt.Printf("loading auth for code code = %+v\n", code)
	if ad, ok := rs.authorize[code]; ok {
		return ad, nil
	}

	rauth, err := rds.Do("GET", fmt.Sprintf("oauth:authorize:%s", code))
	if err != nil {
		return nil, err
	}

	if rauth != nil {

		ad := osin.AuthorizeData{Client: &osin.DefaultClient{}}
		err = gob.NewDecoder(bytes.NewReader(rauth.([]byte))).Decode(&ad)

		if err == nil {
			rs.authorize[ad.Code] = &ad
			return &ad, nil
		}

		log.Println("Decode error", err)
	}

	return nil, fmt.Errorf("TestStorage could not load authorization for code %s", code)
}

//RemoveAuthorize removes authorization data
func (rs *RedisStore) RemoveAuthorize(code string) error {
	delete(rs.authorize, code)
	_, err := rds.Do("DEL", fmt.Sprintf("oauth:authorize:%s", code))
	if err != nil {
		return err
	}
	return nil
}

//SaveAccess saves access data
func (rs *RedisStore) SaveAccess(ad *osin.AccessData) error {
	fmt.Printf("save access ad = %+v\n", ad)
	rs.access[ad.AccessToken] = ad
	fmt.Printf("ts.access = %+v\n", rs.access)

	b := &bytes.Buffer{}
	err := gob.NewEncoder(b).Encode(ad)
	if err != nil {
		log.Println("Error encoding gob access", err)
		return err
	}

	_, err = rds.Do("SET", fmt.Sprintf("oauth:access:%s", ad.AccessToken), b.Bytes())
	if err != nil {
		log.Println("error saving redis oauth:access", err)
	}
	return err
}

//LoadAccess gets access data.
func (rs *RedisStore) LoadAccess(token string) (*osin.AccessData, error) {
	if ad, ok := rs.access[token]; ok {
		fmt.Printf("ad = %+v\n", ad)
		return ad, nil
	}

	bs, err := rds.Do("GET", fmt.Sprintf("oauth:access:%s", token))
	if err != nil {
		log.Println("Error getting oauth access", err)
		return nil, err
	}

	ad := &osin.AccessData{Client: &osin.DefaultClient{}}
	err = gob.NewDecoder(bytes.NewReader(bs.([]byte))).Decode(ad)

	if err != nil {
		log.Println("error decoding access data from gob", err)
		return nil, err
	}

	return nil, fmt.Errorf("Could not find data for token %s", token)
}

//RemoveAccess removes access data.
func (rs *RedisStore) RemoveAccess(token string) error {
	delete(rs.access, token)
	return nil
}

//LoadRefresh gets a refresh token.
func (rs *RedisStore) LoadRefresh(token string) (*osin.AccessData, error) {
	if ad, ok := rs.access[token]; ok {
		return ad, nil
	}
	return nil, fmt.Errorf("Refresh data for token %s not found.", token)
}

//RemoveRefresh removes a refresh token from storage.
func (rs *RedisStore) RemoveRefresh(token string) error {
	if ad, ok := rs.access[token]; ok {
		ad.RefreshToken = ""
	}
	return nil
}
