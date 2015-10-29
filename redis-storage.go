package main

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"log"

	"github.com/RangelReale/osin"
	"github.com/garyburd/redigo/redis"
)

var rds redis.Conn

func init() {
	var err error
	rds, err = redis.Dial("tcp", "localhost:6379")
	if err != nil {
		log.Fatal(err)
	}
}

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
	gob.Register(&osin.DefaultClient{})
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
	// vals, err := redis.Values(rds.Do("HGETALL", "oauth:client:"+id))
	// if err != nil {
	// 	return nil, err
	// }

	if cli, ok := rs.clients[id]; ok {
		return cli, nil
	}
	return &osin.DefaultClient{
		Id:          "1",
		Secret:      "thing",
		RedirectUri: "http://localhost:9000/login",
	}, nil
}

//SaveAuthorize saves authorization
func (rs *RedisStore) SaveAuthorize(ad *osin.AuthorizeData) error {
	rs.authorize[ad.Code] = ad

	fmt.Printf("ad.UserData = %#v\n", ad.UserData)

	b := &bytes.Buffer{}
	err := gob.NewEncoder(b).Encode(ad)
	if err != nil {
		log.Println(err)
		return fmt.Errorf("error encoding gob: %v", err)
	}
	_, err = rds.Do("SET", "oauth:authorize:"+ad.Code, b.Bytes())
	if err != nil {
		log.Println("REDIS error", err)
	}

	return nil
}

//LoadAuthorize loads authorization data by id.
func (rs *RedisStore) LoadAuthorize(code string) (*osin.AuthorizeData, error) {
	if ad, ok := rs.authorize[code]; ok {
		return ad, nil
	}

	rauth, err := rds.Do("GET", "oauth:authorize:"+code)
	if err != nil {
		log.Println("Error finding code", err)
		return nil, err
	}

	if rauth != nil {

		ad := osin.AuthorizeData{}
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
	rds.Do("DEL", "oauth:authorize:"+code)
	return nil
}

//SaveAccess saves access data
func (rs *RedisStore) SaveAccess(ad *osin.AccessData) error {
	rs.access[ad.AccessToken] = ad

	b := &bytes.Buffer{}
	err := gob.NewEncoder(b).Encode(ad)
	if err != nil {
		log.Println("Error encoding gob access", err)
		return err
	}

	_, err = rds.Do("SET", "oauth:access:"+ad.AccessToken, b.Bytes())
	if err != nil {
		log.Println("error saving redis oauth:access", err)
	}
	return err
}

//LoadAccess gets access data.
func (rs *RedisStore) LoadAccess(token string) (*osin.AccessData, error) {
	bs, err := rds.Do("GET", "oauth:access:"+token)
	if err != nil || bs == nil {
		log.Println("Error getting oauth access", err)
		return nil, err
	}

	ad := &osin.AccessData{}
	err = gob.NewDecoder(bytes.NewReader(bs.([]byte))).Decode(ad)

	if err != nil {
		log.Println("error decoding access data from gob", err)
		return nil, err
	}

	fmt.Printf("ad = %+v\n", ad)

	return ad, nil
}

//RemoveAccess removes access data.
func (rs *RedisStore) RemoveAccess(token string) error {
	delete(rs.access, token)
	rds.Do("DEL", "oauth:access:"+token)
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
