// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf
// +build linux_bpf

package http

import (
	"encoding/hex"
	"golang.org/x/net/http2/hpack"
	"strconv"
	"strings"
)

// Path returns the URL from the request fragment captured in eBPF with
// GET variables excluded.
// Example:
// For a request fragment "GET /foo?var=bar HTTP/1.1", this method will return "/foo"
func (tx *ebpfHttp2Tx) Path(buffer []byte) ([]byte, bool) {
	// trim null byte + after
	str, err := hpack.HuffmanDecodeToString(tx.Request_path[:tx.Path_size])
	if err != nil {
		return nil, false
	}
	n := copy(buffer, str)
	// indicate if we knowingly captured the entire path
	return buffer[:n], true
}

// StatusClass returns an integer representing the status code class
// Example: a 404 would return 400
func (tx *ebpfHttp2Tx) StatusClass() int {
	return (int(tx.Response_status_code) / 100) * 100
}

// RequestLatency returns the latency of the request in nanoseconds
func (tx *ebpfHttp2Tx) RequestLatency() float64 {
	if uint64(tx.Request_started) == 0 || uint64(tx.Response_last_seen) == 0 {
		return 0
	}
	return nsTimestampToFloat(tx.Response_last_seen - tx.Request_started)
}

// Incomplete returns true if the transaction contains only the request or response information
// This happens in the context of localhost with NAT, in which case we join the two parts in userspace
func (tx *ebpfHttp2Tx) Incomplete() bool {
	return tx.Request_started == 0 || tx.Response_status_code == 0
}

func (tx *ebpfHttp2Tx) ReqFragment() []byte {
	return tx.Request_fragment[:]
}

func (tx *ebpfHttp2Tx) isIPV4() bool {
	return true
}

func (tx *ebpfHttp2Tx) SrcIPHigh() uint64 {
	return tx.Tup.Saddr_h
}

func (tx *ebpfHttp2Tx) SrcIPLow() uint64 {
	return tx.Tup.Saddr_l
}

func (tx *ebpfHttp2Tx) SrcPort() uint16 {
	return tx.Tup.Sport
}

func (tx *ebpfHttp2Tx) DstIPHigh() uint64 {
	return tx.Tup.Daddr_h
}

func (tx *ebpfHttp2Tx) DstIPLow() uint64 {
	return tx.Tup.Daddr_l
}

func (tx *ebpfHttp2Tx) DstPort() uint16 {
	return tx.Tup.Dport
}

func (tx *ebpfHttp2Tx) Method() Method {
	return Method(tx.Request_method)
}

func (tx *ebpfHttp2Tx) StatusCode() uint16 {
	return tx.Response_status_code
}

func (tx *ebpfHttp2Tx) SetStatusCode(code uint16) {
	tx.Response_status_code = code
}

func (tx *ebpfHttp2Tx) ResponseLastSeen() uint64 {
	return tx.Response_last_seen
}

func (tx *ebpfHttp2Tx) SetResponseLastSeen(lastSeen uint64) {
	tx.Response_last_seen = lastSeen

}
func (tx *ebpfHttp2Tx) RequestStarted() uint64 {
	return tx.Request_started
}

func (tx *ebpfHttp2Tx) RequestMethod() uint32 {
	return uint32(tx.Request_method)
}

func (tx *ebpfHttp2Tx) SetRequestMethod(m uint32) {
	tx.Request_method = uint8(m)
}

// StaticTags returns an uint64 representing the tags bitfields
// Tags are defined here : pkg/network/ebpf/kprobe_types.go
func (tx *ebpfHttp2Tx) StaticTags() uint64 {
	return tx.Tags
}

func (tx *ebpfHttp2Tx) DynamicTags() []string {
	return nil
}

func (tx *ebpfHttp2Tx) String() string {
	var output strings.Builder
	output.WriteString("ebpfHttp2Tx{")
	output.WriteString("Method: '" + Method(tx.Request_method).String() + "', ")
	output.WriteString("Tags: '0x" + strconv.FormatUint(tx.Tags, 16) + "', ")
	output.WriteString("Fragment: '" + hex.EncodeToString(tx.Request_fragment[:]) + "', ")
	output.WriteString("}")
	return output.String()
}
