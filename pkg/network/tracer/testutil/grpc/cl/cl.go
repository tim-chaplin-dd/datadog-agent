package main

import (
	"context"
	"fmt"
	"github.com/DataDog/datadog-agent/pkg/network/tracer/testutil/grpc"
	"strconv"
)

func main() {
	c, err := grpc.NewClient("127.0.0.1:5050", grpc.Options{})
	if err != nil {
		panic(c)
	}

	for i := 0; i < 3; i++ {
		fmt.Scanln()
		c.HandleUnary(context.Background(), "hey"+strconv.Itoa(i+1))
	}
}
