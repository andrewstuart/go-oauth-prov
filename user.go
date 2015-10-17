package main

import (
	"errors"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/garyburd/redigo/redis"
	"golang.org/x/crypto/bcrypt"
)

//User is a hashed password
type User struct {
	Password []byte `redis:"password"`
}

const loginAttempts int64 = 10

var errExceededAttempts = errors.New("login count has been exceeded")

type userPass struct {
	Username, Pass string
}

func (up *userPass) path(path ...string) string {
	u := "oauth:users:" + up.Username
	if len(path) > 0 {
		u += ":" + strings.Join(path, ":")
	}
	return u
}

//Validate a user/pass within redis
func validateUser(up userPass) (bool, error) {
	ct, err := rds.Do("HINCRBY", up.path(), "attempts", 1)
	if err != nil {
		return false, err
	}

	if ct.(int64) > loginAttempts {
		rds.Send("MULTI")
		rds.Send("HSETNX", up.path(), "reset", time.Now().Add(10*time.Second).Unix())
		rds.Send("HGET", up.path(), "reset")

		res, err := rds.Do("EXEC")
		if err != nil {
			return false, err
		}

		unix, err := strconv.ParseInt(string((res.([]interface{}))[1].([]byte)), 10, 64)

		//If the reset time is not in the past, return err
		if err == nil && time.Unix(int64(unix), 0).Before(time.Now()) {
			defer func() {
				//Clear out password attempts
				rds.Send("MULTI")
				rds.Send("HDEL", up.path(), "reset")
				rds.Send("HDEL", up.path(), "attempts")
				rds.Do("EXEC")
			}()
		} else {
			if err != nil {
				log.Println("login attempt reset error", err)
			}
			return false, errExceededAttempts
		}
	}

	vals, err := redis.Values(rds.Do("HGETALL", up.path()))
	if err != nil || vals == nil {
		return false, err
	}

	var u User
	if err := redis.ScanStruct(vals, &u); err != nil {
		return false, err
	}

	bcErr := bcrypt.CompareHashAndPassword(u.Password, []byte(up.Pass))

	valid := bcErr == nil

	if valid {
		defer rds.Do("HDECRBY", up.path(), "attempts", 1)
	}

	return valid, bcErr
}
