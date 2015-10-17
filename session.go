package main

import (
	"crypto/rand"
	"encoding/base64"
	"log"
	"net/http"
	"time"

	"github.com/garyburd/redigo/redis"
)

const (
	sessSize   = 50
	dateFormat = time.RFC3339
)

type session struct {
	UserName   string `redis:"user"`
	Expiration string `redis:"exp"`
}

func (s *session) isValid() bool {
	t, err := time.Parse(dateFormat, s.Expiration)
	if err != nil {
		log.Println("error parsing redis session exp date", err)
		return false
	}
	return t.After(time.Now())
}

func checkSession(r *http.Request) bool {
	log.Println("Check Session")
	c, err := r.Cookie("sess")
	if err != nil {
		log.Println("cookie error", err)
		return false
	}

	log.Println(c)
	vals, err := redis.Values(rds.Do("HGETALL", "cookie:"+c.Value))
	if err != nil {
		log.Println("Could not find cookie", err)
		return false
	}

	var storedSession session

	err = redis.ScanStruct(vals, &storedSession)
	if err != nil {
		log.Println("Invalid session data from redis", err)
	}

	return storedSession.isValid()
}

func writeSession(w http.ResponseWriter, user string) {
	sess := make([]byte, sessSize)

	n, err := rand.Read(sess)

	if err != nil {
		log.Println("Session key generation error", err)
		return
	}

	if n < len(sess) {
		log.Println("Short read from crypto", err)
		return
	}

	c := &http.Cookie{
		Name:    "sess",
		Value:   base64.StdEncoding.EncodeToString(sess),
		Expires: time.Now().Add(time.Hour),
		Secure:  false,
	}

	_, err = rds.Do("HMSET", "cookie:"+c.Value, "user", user, "exp", c.Expires.Format(dateFormat))
	if err != nil {
		log.Println("Couldn't set user cookie in redis", err)
	}

	http.SetCookie(w, c)
}
