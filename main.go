package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/0xrawsec/golang-etw/etw"
	"github.com/lkarlslund/hashmuncher/modules"
)

type ProviderEventID struct {
	Provider string
	EventID  uint16
}

func main() {
	s := etw.NewRealTimeSession(randomString(32))
	defer s.Stop()

	modulemap := make(map[ProviderEventID]Module)

	modulelist := []Module{&modules.NTLMHash{}}
	for _, module := range modulelist {
		provider, err := module.Init()
		if err != nil {
			panic(err)
		}

		for _, eventid := range provider.Filter {
			modulemap[ProviderEventID{Provider: provider.GUID, EventID: eventid}] = module
		}

		if err := s.EnableProvider(provider); err != nil {
			panic(err)
		}
	}

	// Consuming from the trace
	c := etw.NewRealTimeConsumer(context.Background())
	defer c.Stop()

	c.FromSessions(s)

	go func() {
		var b []byte
		var err error
		for e := range c.Events {
			if module, found := modulemap[ProviderEventID{Provider: e.System.Provider.Guid, EventID: e.System.EventID}]; found {
				module.ProcessEvent(e)
			} else {
				if b, err = json.Marshal(e); err != nil {
					panic(err)
				}
				fmt.Println(string(b))
			}
		}
	}()

	if err := c.Start(); err != nil {
		panic(err)
	}

	sigchan := make(chan os.Signal)
	signal.Notify(sigchan, os.Interrupt, syscall.SIGTERM)
	<-sigchan
}
