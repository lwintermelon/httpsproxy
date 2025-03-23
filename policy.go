package httpsproxy

import (
	"sync"
)

type HttpAction int

const (
	Forward HttpAction = iota
	Block
	ModifiyHeader
	Default
)

type Policy struct {
	sm sync.Map
}

func (d *Policy) GetHostAction(host string) HttpAction {
	if v, ok := d.sm.Load(host); ok {
		return v.(HttpAction)
	}
	return Default
}

func (d *Policy) UpdateHostAction(host string, action HttpAction) {
	d.sm.Store(host, action)
}

func CreatePolicy(m map[string]HttpAction) *Policy {
	d := &Policy{sm: sync.Map{}}
	if m == nil {
		return d
	}
	for k, v := range m {
		d.UpdateHostAction(k, v)
	}
	return d
}
