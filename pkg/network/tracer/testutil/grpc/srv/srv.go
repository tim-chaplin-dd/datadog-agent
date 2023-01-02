package main

import (
	"fmt"
	"github.com/DataDog/datadog-agent/pkg/network/tracer/testutil/grpc"
)

func main() {
	s, err := grpc.NewServer("127.0.0.1:5050")
	if err != nil {
		panic(err)
	}

	s.Run()
	fmt.Scanln()
	s.Stop()
}
