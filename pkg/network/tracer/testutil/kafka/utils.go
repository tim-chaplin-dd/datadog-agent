// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package kafka

import (
	"fmt"
	"github.com/DataDog/datadog-agent/pkg/network/protocols/http/testutil"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/segmentio/kafka-go"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/context"
)

func tryConnectingKafka(addr string) bool {
	dialer := &kafka.Dialer{
		Timeout: time.Second,
	}
	conn, err := dialer.Dial("tcp", addr)
	if err != nil {
		return false
	}
	defer conn.Close()

	_, err = conn.ApiVersions()
	return err == nil
}

func waitForKafka(ctx context.Context, kafkaAddr string) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			if tryConnectingKafka(kafkaAddr) {
				return nil
			}
			time.Sleep(time.Second)
			continue
		}
	}
}

func PullKafkaDockers() error {
	dir, _ := testutil.CurDir()
	envs := []string{
		"KAFKA_ADDR=127.0.0.1",
		"KAFKA_PORT=9092",
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker-compose", "-f", dir+"/testdata/docker-compose.yml", "pull")
	cmd.Env = append(cmd.Env, envs...)
	return cmd.Run()
}

func RunKafkaServers(t *testing.T, serverAddr string) {
	t.Helper()
	envs := []string{
		fmt.Sprintf("KAFKA_ADDR=%s", serverAddr),
		"KAFKA_PORT=9092",
	}
	dir, _ := testutil.CurDir()
	cmd := exec.Command("docker-compose", "-f", dir+"/testdata/docker-compose.yml", "up")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stdout
	cmd.Env = append(cmd.Env, envs...)
	go func() {
		if err := cmd.Run(); err != nil {
			fmt.Println("error", err)
		}
	}()

	t.Cleanup(func() {
		c := exec.Command("docker-compose", "-f", dir+"/testdata/docker-compose.yml", "down", "--remove-orphans")
		c.Stdout = os.Stdout
		c.Stderr = os.Stdout
		c.Env = append(c.Env, envs...)
		_ = c.Run()
	})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	require.NoError(t, waitForKafka(ctx, fmt.Sprintf("%s:9092", serverAddr)))
	cancel()
}
