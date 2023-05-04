package main

import "github.com/0xrawsec/golang-etw/etw"

type Module interface {
	Init() (etw.Provider, error)
	ProcessEvent(e *etw.Event)
}
