package main

import "github.com/0xrawsec/golang-etw/etw"

type Module interface {
	Init(resultchan chan<- ModuleResult) (etw.Provider, error)
	ProcessEvent(e *etw.Event)
}

type ModuleResult interface {
	String() string
}
