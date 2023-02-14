// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf
// +build linux_bpf

package tracer

import (
	"fmt"
	"testing"

	"github.com/cilium/ebpf/btf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/DataDog/datadog-agent/pkg/ebpf"
	netebpf "github.com/DataDog/datadog-agent/pkg/network/ebpf"
)

func TestOffsetGuessAgainstBTF(t *testing.T) {
	cfg := testConfig()
	offsetBuf, err := netebpf.ReadOffsetBPFModule(cfg.BPFDir, cfg.BPFDebug)
	require.NoError(t, err)
	defer offsetBuf.Close()

	constantEditors, err := runOffsetGuessing(cfg, offsetBuf)
	require.NoError(t, err)

	btfdata, _ := ebpf.GetBTF(cfg.BTFPath, cfg.BPFDir)
	require.NotNil(t, btfdata)

	var sk *btf.Struct
	err = btfdata.TypeByName("sock", &sk)
	require.NoError(t, err)

	var inet_sock *btf.Struct
	err = btfdata.TypeByName("inet_sock", &inet_sock)
	require.NoError(t, err)

	var sk_common *btf.Struct
	err = btfdata.TypeByName("sock_common", &sk_common)
	require.NoError(t, err)

	var net *btf.Struct
	err = btfdata.TypeByName("net", &net)
	require.NoError(t, err)

	var tcp_sock *btf.Struct
	err = btfdata.TypeByName("tcp_sock", &tcp_sock)
	require.NoError(t, err)

	var flowi4 *btf.Struct
	err = btfdata.TypeByName("flowi4", &flowi4)
	require.NoError(t, err)

	var flowi_uli *btf.Union
	err = btfdata.TypeByName("flowi_uli", &flowi_uli)
	require.NoError(t, err)

	var flowi6 *btf.Struct
	err = btfdata.TypeByName("flowi6", &flowi6)
	require.NoError(t, err)

	var sk_buff *btf.Struct
	err = btfdata.TypeByName("sk_buff", &sk_buff)
	require.NoError(t, err)

	sk_common_offset, _, err := getOffset(sk.Members, "__sk_common")
	require.NoError(t, err)

	for _, ce := range constantEditors {
		t.Run(ce.Name, func(t *testing.T) {
			switch ce.Name {
			case "offset_saddr":
				off, _, err := getOffset(sk_common.Members, "skc_rcv_saddr")
				if assert.NoError(t, err, ce.Name) {
					assert.Equal(t, uint64(sk_common_offset+off), ce.Value.(uint64), ce.Name)
				}
			case "offset_daddr":
				off, _, err := getOffset(sk_common.Members, "skc_daddr")
				if assert.NoError(t, err, ce.Name) {
					assert.Equal(t, uint64(sk_common_offset+off), ce.Value.(uint64), ce.Name)
				}
			case "offset_sport":
				// this ends up guessing inet_sock.inet_sport rather than sk_common.skc_num
				off, _, err := getOffset(inet_sock.Members, "inet_sport")
				if assert.NoError(t, err, ce.Name) {
					assert.Equal(t, uint64(off), ce.Value.(uint64), ce.Name)
				}
			case "offset_dport":
				off, _, err := getOffset(sk_common.Members, "skc_dport")
				if assert.NoError(t, err, ce.Name) {
					assert.Equal(t, uint64(sk_common_offset+off), ce.Value.(uint64), ce.Name)
				}
			case "offset_netns":
				off, _, err := getOffset(sk_common.Members, "skc_net")
				if assert.NoError(t, err, ce.Name) {
					assert.Equal(t, uint64(sk_common_offset+off), ce.Value.(uint64), ce.Name)
				}
			case "offset_family":
				off, _, err := getOffset(sk_common.Members, "skc_family")
				if assert.NoError(t, err, ce.Name) {
					assert.Equal(t, uint64(sk_common_offset+off), ce.Value.(uint64), ce.Name)
				}
			case "offset_daddr_ipv6":
				off, _, err := getOffset(sk_common.Members, "skc_v6_daddr")
				if assert.NoError(t, err, ce.Name) {
					assert.Equal(t, uint64(sk_common_offset+off), ce.Value.(uint64), ce.Name)
				}
			case "offset_ino":
				netOff, _, err := getOffset(net.Members, "ns")
				if err == nil {
					var inumOff uint32
					var ns_common *btf.Struct
					err = btfdata.TypeByName("ns_common", &ns_common)
					if assert.NoError(t, err, "%s:ns_common", ce.Name) {
						inumOff, _, err = getOffset(ns_common.Members, "inum")
						netOff += inumOff
					}
				} else {
					netOff, _, err = getOffset(net.Members, "proc_inum")
				}
				// fallthrough error from both branches
				if assert.NoError(t, err, ce.Name) {
					assert.Equal(t, uint64(netOff), ce.Value.(uint64), ce.Name)
				}
			case "offset_rtt":
				off, _, err := getOffset(tcp_sock.Members, "srtt_us")
				if assert.NoError(t, err, ce.Name) {
					assert.Equal(t, uint64(off), ce.Value.(uint64), ce.Name)
				}
			case "offset_rtt_var":
				off, _, err := getOffset(tcp_sock.Members, "mdev_us")
				if assert.NoError(t, err, ce.Name) {
					assert.Equal(t, uint64(off), ce.Value.(uint64), ce.Name)
				}
			case "offset_saddr_fl4":
				off, _, err := getOffset(flowi4.Members, "saddr")
				if assert.NoError(t, err, ce.Name) {
					assert.Equal(t, uint64(off), ce.Value.(uint64), ce.Name)
				}
			case "offset_daddr_fl4":
				off, _, err := getOffset(flowi4.Members, "daddr")
				if assert.NoError(t, err, ce.Name) {
					assert.Equal(t, uint64(off), ce.Value.(uint64), ce.Name)
				}
			case "offset_sport_fl4":
				off, _, err := getOffset(flowi4.Members, "uli")
				if assert.NoError(t, err, ce.Name) {
					floff, _, err := getOffset(flowi_uli.Members, "sport")
					if assert.NoError(t, err, ce.Name) {
						assert.Equal(t, uint64(off+floff), ce.Value.(uint64), ce.Name)
					}
				}
			case "offset_dport_fl4":
				off, _, err := getOffset(flowi4.Members, "uli")
				if assert.NoError(t, err, ce.Name) {
					floff, _, err := getOffset(flowi_uli.Members, "dport")
					if assert.NoError(t, err, ce.Name) {
						assert.Equal(t, uint64(off+floff), ce.Value.(uint64), ce.Name)
					}
				}
			case "offset_saddr_fl6":
				off, _, err := getOffset(flowi6.Members, "saddr")
				if assert.NoError(t, err, ce.Name) {
					assert.Equal(t, uint64(off), ce.Value.(uint64), ce.Name)
				}
			case "offset_daddr_fl6":
				off, _, err := getOffset(flowi6.Members, "daddr")
				if assert.NoError(t, err, ce.Name) {
					assert.Equal(t, uint64(off), ce.Value.(uint64), ce.Name)
				}
			case "offset_sport_fl6":
				off, _, err := getOffset(flowi6.Members, "uli")
				if assert.NoError(t, err, ce.Name) {
					floff, _, err := getOffset(flowi_uli.Members, "sport")
					if assert.NoError(t, err, ce.Name) {
						assert.Equal(t, uint64(off+floff), ce.Value.(uint64), ce.Name)
					}
				}
			case "offset_dport_fl6":
				off, _, err := getOffset(flowi6.Members, "uli")
				if assert.NoError(t, err, ce.Name) {
					floff, _, err := getOffset(flowi_uli.Members, "dport")
					if assert.NoError(t, err, ce.Name) {
						assert.Equal(t, uint64(off+floff), ce.Value.(uint64), ce.Name)
					}
				}
			case "offset_socket_sk":
				var socket *btf.Struct
				err = btfdata.TypeByName("socket", &socket)
				if assert.NoError(t, err) {
					off, _, err := getOffset(socket.Members, "sk")
					if assert.NoError(t, err, ce.Name) {
						assert.Equal(t, uint64(off), ce.Value.(uint64), ce.Name)
					}
				}
			case "offset_sk_buff_sock":
				off, _, err := getOffset(sk_buff.Members, "sk")
				if assert.NoError(t, err, ce.Name) {
					assert.Equal(t, uint64(off), ce.Value.(uint64), ce.Name)
				}
			case "offset_sk_buff_transport_header":
				off, _, err := getOffset(sk_buff.Members, "transport_header")
				if assert.NoError(t, err, ce.Name) {
					assert.Equal(t, uint64(off), ce.Value.(uint64), ce.Name)
				}
			case "offset_sk_buff_head":
				off, _, err := getOffset(sk_buff.Members, "head")
				if assert.NoError(t, err, ce.Name) {
					assert.Equal(t, uint64(off), ce.Value.(uint64), ce.Name)
				}
			default:
				t.SkipNow()
			}
		})
	}
}

func getOffset(members []btf.Member, name string) (uint32, btf.Member, error) {
	for _, m := range members {
		if m.Name == name {
			return m.Offset.Bytes(), m, nil
		}
		switch v := m.Type.(type) {
		case *btf.Union:
			if off, vm, err := getOffset(v.Members, name); err == nil {
				return m.Offset.Bytes() + off, vm, nil
			}
		case *btf.Struct:
			if v.Name == "" {
				if off, vm, err := getOffset(v.Members, name); err == nil {
					return m.Offset.Bytes() + off, vm, nil
				}
			}
		}
	}
	return 0, btf.Member{}, fmt.Errorf("%s member not found", name)
}
