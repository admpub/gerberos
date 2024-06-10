package gerberos

import (
	"net"
	"sync"
	"time"

	"github.com/admpub/regexp2"
)

type aggregate struct {
	registry      map[string]net.IP
	registryMutex sync.Mutex
	interval      time.Duration
	regexp        []*regexp2.Regexp
}

func newAggregate(interval time.Duration, res []*regexp2.Regexp) *aggregate {
	return &aggregate{
		registry: make(map[string]net.IP),
		interval: interval,
		regexp:   res,
	}
}
