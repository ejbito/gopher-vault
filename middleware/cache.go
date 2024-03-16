package middleware

import (
	"time"

	"github.com/patrickmn/go-cache"
)

var Blacklist = cache.New(time.Minute*5, time.Minute*10)