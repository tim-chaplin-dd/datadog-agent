// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package eval

import "unsafe"

// Iterator interface of a field iterator
type Iterator[T any] interface {
	Front(ctx *Context[T]) unsafe.Pointer
	Next() unsafe.Pointer
}
