package main

import (
	"github.com/garyburd/redigo/redis"
	"golang.org/x/crypto/bcrypt"
)

//User is a hashed password
type User struct {
	Password []byte `redis:"password"`
}

func validateUser(username, password string) (bool, error) {
	vals, err := redis.Values(rds.Do("HGETALL", "oauth:users:"+username))
	if err != nil || vals == nil {
		return false, err
	}

	var u User
	if err := redis.ScanStruct(vals, &u); err != nil {
		return false, err
	}

	bcErr := bcrypt.CompareHashAndPassword(u.Password, []byte(password))
	return bcErr == nil, bcErr
}
