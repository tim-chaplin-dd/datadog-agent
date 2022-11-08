// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build !linux
// +build !linux

package config

import "errors"

func getCgroupCPULimit() (float64, error) {
	return 0, errors.New("cgroup cpu limit not support outside linux environments")
}
