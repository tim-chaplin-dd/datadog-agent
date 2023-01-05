package grpc

import (
	"context"
	"fmt"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"
	"strings"
	"testing"
)

const (
	srvAddr = "127.0.0.1:5050"
)

// c is a stream endpoint
// a + b are unary endpoints
func TestGRPCScenarios(t *testing.T) {
	tests := []struct {
		name       string
		runClients func(t *testing.T, differentClients bool)
	}{
		{
			name: "unary, a->a->a",
			runClients: func(t *testing.T, differentClients bool) {
				var client1, client2 Client
				var err error
				client1, err = NewClient(srvAddr, Options{})
				require.NoError(t, err)
				client2 = client1
				if differentClients {
					client2, err = NewClient(srvAddr, Options{})
					require.NoError(t, err)
				}

				ctx := context.Background()
				require.NoError(t, client1.HandleUnary(ctx, "first"))
				require.NoError(t, client2.HandleUnary(ctx, "second"))
				require.NoError(t, client1.HandleUnary(ctx, "third"))
			},
		},
		{
			name: "unary, a->b->a->b",
			runClients: func(t *testing.T, differentClients bool) {
				var client1, client2 Client
				var err error
				client1, err = NewClient(srvAddr, Options{})
				require.NoError(t, err)
				client2 = client1
				if differentClients {
					client2, err = NewClient(srvAddr, Options{})
					require.NoError(t, err)
				}

				ctx := context.Background()
				require.NoError(t, client1.HandleUnary(ctx, "first"))
				require.NoError(t, client2.GetFeature(ctx, -746143763, 407838351))
				require.NoError(t, client1.HandleUnary(ctx, "third"))
				require.NoError(t, client2.GetFeature(ctx, -743999179, 408122808))
			},
		},
		{
			name: "unary, a->b->b->a",
			runClients: func(t *testing.T, differentClients bool) {
				var client1, client2 Client
				var err error
				client1, err = NewClient(srvAddr, Options{})
				require.NoError(t, err)
				client2 = client1
				if differentClients {
					client2, err = NewClient(srvAddr, Options{})
					require.NoError(t, err)
				}

				ctx := context.Background()
				require.NoError(t, client1.HandleUnary(ctx, "first"))
				require.NoError(t, client2.GetFeature(ctx, -746143763, 407838351))
				require.NoError(t, client1.GetFeature(ctx, -743999179, 408122808))
				require.NoError(t, client2.HandleUnary(ctx, "third"))
			},
		},
		{
			name: "unary, a->b->b->a",
			runClients: func(t *testing.T, differentClients bool) {
				var client1, client2 Client
				var err error
				client1, err = NewClient(srvAddr, Options{})
				require.NoError(t, err)
				client2 = client1
				if differentClients {
					client2, err = NewClient(srvAddr, Options{})
					require.NoError(t, err)
				}

				ctx := context.Background()
				require.NoError(t, client1.HandleUnary(ctx, "first"))
				require.NoError(t, client2.GetFeature(ctx, -746143763, 407838351))
				require.NoError(t, client2.GetFeature(ctx, -743999179, 408122808))
				require.NoError(t, client1.HandleUnary(ctx, "third"))
			},
		},
		{
			name: "stream, c->c->c",
			runClients: func(t *testing.T, differentClients bool) {
				var client1, client2 Client
				var err error
				client1, err = NewClient(srvAddr, Options{})
				require.NoError(t, err)
				client2 = client1
				if differentClients {
					client2, err = NewClient(srvAddr, Options{})
					require.NoError(t, err)
				}

				ctx := context.Background()
				require.NoError(t, client1.HandleStream(ctx, 10))
				require.NoError(t, client2.HandleStream(ctx, 10))
				require.NoError(t, client1.HandleStream(ctx, 10))
			},
		},
		{
			name: "mixed, c->b->c->b",
			runClients: func(t *testing.T, differentClients bool) {
				var client1, client2 Client
				var err error
				client1, err = NewClient(srvAddr, Options{})
				require.NoError(t, err)
				client2 = client1
				if differentClients {
					client2, err = NewClient(srvAddr, Options{})
					require.NoError(t, err)
				}

				ctx := context.Background()
				require.NoError(t, client1.HandleStream(ctx, 10))
				require.NoError(t, client2.HandleUnary(ctx, "first"))
				require.NoError(t, client1.HandleStream(ctx, 10))
				require.NoError(t, client2.HandleUnary(ctx, "second"))
			},
		},
		{
			name: "mixed, c->b->c->b",
			runClients: func(t *testing.T, differentClients bool) {
				var client1, client2 Client
				var err error
				client1, err = NewClient(srvAddr, Options{})
				require.NoError(t, err)
				client2 = client1
				if differentClients {
					client2, err = NewClient(srvAddr, Options{})
					require.NoError(t, err)
				}

				ctx := context.Background()
				require.NoError(t, client1.HandleStream(ctx, 10))
				require.NoError(t, client1.HandleUnary(ctx, "first"))
				require.NoError(t, client2.HandleStream(ctx, 10))
				require.NoError(t, client2.HandleUnary(ctx, "second"))
			},
		},
		{
			name: "request with large body (1MB) -> b -> request with large body (1MB) -> b",
			runClients: func(t *testing.T, differentClients bool) {
				var client1, client2 Client
				var err error
				client1, err = NewClient(srvAddr, Options{})
				require.NoError(t, err)
				client2 = client1
				if differentClients {
					client2, err = NewClient(srvAddr, Options{})
					require.NoError(t, err)
				}

				longName := strings.Repeat("1", 1024*1024)
				ctx := context.Background()
				require.NoError(t, client1.HandleUnary(ctx, longName))
				require.NoError(t, client2.GetFeature(ctx, -746143763, 407838351))
				require.NoError(t, client1.HandleUnary(ctx, longName))
				require.NoError(t, client2.GetFeature(ctx, -743999179, 408122808))
			},
		},
		{
			name: "request with large body (1MB) -> b -> request with large body (1MB) -> b",
			runClients: func(t *testing.T, differentClients bool) {
				var client1, client2 Client
				var err error
				client1, err = NewClient(srvAddr, Options{})
				require.NoError(t, err)
				client2 = client1
				if differentClients {
					client2, err = NewClient(srvAddr, Options{})
					require.NoError(t, err)
				}

				longName := strings.Repeat("1", 1024*1024)
				ctx := context.Background()
				require.NoError(t, client1.HandleUnary(ctx, longName))
				require.NoError(t, client2.GetFeature(ctx, -746143763, 407838351))
				require.NoError(t, client2.HandleUnary(ctx, longName))
				require.NoError(t, client1.GetFeature(ctx, -743999179, 408122808))
			},
		},
		{
			name: "500 headers -> b -> 500 headers -> b",
			runClients: func(t *testing.T, differentClients bool) {
				var client1, client2 Client
				var err error
				client1, err = NewClient(srvAddr, Options{})
				require.NoError(t, err)
				client2 = client1
				if differentClients {
					client2, err = NewClient(srvAddr, Options{})
					require.NoError(t, err)
				}

				ctxWithoutHeaders := context.Background()
				ctxWithHeaders := context.Background()
				headers := make(map[string]string, 500)
				for i := 1; i <= 500; i++ {
					headers[fmt.Sprintf("header-%d", i)] = fmt.Sprintf("value-%d", i)
				}
				md := metadata.New(headers)
				ctxWithHeaders = metadata.NewOutgoingContext(ctxWithHeaders, md)
				longName := strings.Repeat("1", 1024*1024)
				require.NoError(t, client1.HandleUnary(ctxWithHeaders, longName))
				require.NoError(t, client2.GetFeature(ctxWithoutHeaders, -746143763, 407838351))
				require.NoError(t, client1.HandleUnary(ctxWithHeaders, longName))
				require.NoError(t, client2.GetFeature(ctxWithoutHeaders, -743999179, 408122808))
			},
		},
		{
			name: "500 headers -> b -> 500 headers -> b",
			runClients: func(t *testing.T, differentClients bool) {
				var client1, client2 Client
				var err error
				client1, err = NewClient(srvAddr, Options{})
				require.NoError(t, err)
				client2 = client1
				if differentClients {
					client2, err = NewClient(srvAddr, Options{})
					require.NoError(t, err)
				}

				ctxWithoutHeaders := context.Background()
				ctxWithHeaders := context.Background()
				headers := make(map[string]string, 500)
				for i := 1; i <= 500; i++ {
					headers[fmt.Sprintf("header-%d", i)] = fmt.Sprintf("value-%d", i)
				}
				md := metadata.New(headers)
				ctxWithHeaders = metadata.NewOutgoingContext(ctxWithHeaders, md)
				longName := strings.Repeat("1", 1024*1024)
				require.NoError(t, client1.HandleUnary(ctxWithHeaders, longName))
				require.NoError(t, client2.GetFeature(ctxWithoutHeaders, -746143763, 407838351))
				require.NoError(t, client2.HandleUnary(ctxWithHeaders, longName))
				require.NoError(t, client1.GetFeature(ctxWithoutHeaders, -743999179, 408122808))
			},
		},
		{
			name: "duplicated headers -> b -> duplicated headers -> b",
			runClients: func(t *testing.T, differentClients bool) {
				var client1, client2 Client
				var err error
				client1, err = NewClient(srvAddr, Options{})
				require.NoError(t, err)
				client2 = client1
				if differentClients {
					client2, err = NewClient(srvAddr, Options{})
					require.NoError(t, err)
				}

				ctxWithoutHeaders := context.Background()
				ctxWithHeaders := context.Background()
				headers := make(map[string]string, 20)
				for i := 1; i <= 20; i++ {
					headers[fmt.Sprintf("header-%d", i)] = fmt.Sprintf("value")
				}
				md := metadata.New(headers)
				ctxWithHeaders = metadata.NewOutgoingContext(ctxWithHeaders, md)
				longName := strings.Repeat("1", 1024*1024)
				require.NoError(t, client1.HandleUnary(ctxWithHeaders, longName))
				require.NoError(t, client2.GetFeature(ctxWithoutHeaders, -746143763, 407838351))
				require.NoError(t, client1.HandleUnary(ctxWithHeaders, longName))
				require.NoError(t, client2.GetFeature(ctxWithoutHeaders, -743999179, 408122808))
			},
		},
		{
			name: "duplicated headers -> b -> duplicated headers -> b",
			runClients: func(t *testing.T, differentClients bool) {
				var client1, client2 Client
				var err error
				client1, err = NewClient(srvAddr, Options{})
				require.NoError(t, err)
				client2 = client1
				if differentClients {
					client2, err = NewClient(srvAddr, Options{})
					require.NoError(t, err)
				}

				ctxWithoutHeaders := context.Background()
				ctxWithHeaders := context.Background()
				headers := make(map[string]string, 20)
				for i := 1; i <= 20; i++ {
					headers[fmt.Sprintf("header-%d", i)] = fmt.Sprintf("value")
				}
				md := metadata.New(headers)
				ctxWithHeaders = metadata.NewOutgoingContext(ctxWithHeaders, md)
				longName := strings.Repeat("1", 1024*1024)
				require.NoError(t, client1.HandleUnary(ctxWithHeaders, longName))
				require.NoError(t, client2.GetFeature(ctxWithoutHeaders, -746143763, 407838351))
				require.NoError(t, client2.HandleUnary(ctxWithHeaders, longName))
				require.NoError(t, client1.GetFeature(ctxWithoutHeaders, -743999179, 408122808))
			},
		},
	}
	for _, tt := range tests {
		for _, val := range []bool{false, true} {
			s := fmt.Sprintf("different clients - %v", val)
			t.Run(tt.name+s, func(t *testing.T) {
				s, err := NewServer("127.0.0.1:5050")
				require.NoError(t, err)
				s.Run()
				t.Cleanup(s.Stop)

				tt.runClients(t, val)
			})
		}
	}
}
