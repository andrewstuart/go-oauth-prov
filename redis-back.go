package main

import (
	"log"

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
