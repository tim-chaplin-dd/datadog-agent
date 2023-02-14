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

	"github.com/cihub/seelog"
	"github.com/cilium/ebpf/btf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/DataDog/datadog-agent/pkg/ebpf"
	netebpf "github.com/DataDog/datadog-agent/pkg/network/ebpf"
	"github.com/DataDog/datadog-agent/pkg/network/tracer/connection/kprobe"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

func TestOffsetGuessAgainstBTF(t *testing.T) {
	lvl, _ := log.GetLogLevel()
	log.ChangeLogLevel(seelog.Default, "trace")
	t.Cleanup(func() {
		log.ChangeLogLevel(seelog.Default, lvl.String())
	})

	cfg := testConfig()
	offsetBuf, err := netebpf.ReadOffsetBPFModule(cfg.BPFDir, cfg.BPFDebug)
	require.NoError(t, err)
	defer offsetBuf.Close()

	protocolClassificationSupported := kprobe.ClassificationSupported(cfg)

	constantEditors, err := runOffsetGuessing(cfg, offsetBuf)
	require.NoError(t, err)

	btfdata, _ := ebpf.GetBTF(cfg.BTFPath, cfg.BPFDir)
	require.NotNil(t, btfdata)

	sock := getFirstStruct(t, btfdata, "sock")
	inet_sock := getFirstStruct(t, btfdata, "inet_sock")
	sock_common := getFirstStruct(t, btfdata, "sock_common")
	net := getFirstStruct(t, btfdata, "net")
	tcp_sock := getFirstStruct(t, btfdata, "tcp_sock")
	flowi4 := getFirstStruct(t, btfdata, "flowi4")
	flowi_uli := getFirstUnion(t, btfdata, "flowi_uli")
	flowi6 := getFirstStruct(t, btfdata, "flowi6")
	sk_buff := getFirstStruct(t, btfdata, "sk_buff")

	sk_common_offset, _, err := getOffset(sock.Members, "__sk_common")
	require.NoError(t, err)

	for _, ce := range constantEditors {
		t.Run(ce.Name, func(t *testing.T) {
			switch ce.Name {
			case "offset_saddr":
				off, _, err := getOffset(sock_common.Members, "skc_rcv_saddr")
				if assert.NoError(t, err, ce.Name) {
					assert.Equal(t, uint64(sk_common_offset+off), ce.Value.(uint64), ce.Name)
				}
			case "offset_daddr":
				off, _, err := getOffset(sock_common.Members, "skc_daddr")
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
				off, _, err := getOffset(sock_common.Members, "skc_dport")
				if assert.NoError(t, err, ce.Name) {
					assert.Equal(t, uint64(sk_common_offset+off), ce.Value.(uint64), ce.Name)
				}
			case "offset_netns":
				off, _, err := getOffset(sock_common.Members, "skc_net")
				if assert.NoError(t, err, ce.Name) {
					assert.Equal(t, uint64(sk_common_offset+off), ce.Value.(uint64), ce.Name)
				}
			case "offset_family":
				off, _, err := getOffset(sock_common.Members, "skc_family")
				if assert.NoError(t, err, ce.Name) {
					assert.Equal(t, uint64(sk_common_offset+off), ce.Value.(uint64), ce.Name)
				}
			case "offset_daddr_ipv6":
				off, _, err := getOffset(sock_common.Members, "skc_v6_daddr")
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
				socket := getFirstStruct(t, btfdata, "socket")
				if assert.NoError(t, err) {
					off, _, err := getOffset(socket.Members, "sk")
					if assert.NoError(t, err, ce.Name) {
						assert.Equal(t, uint64(off), ce.Value.(uint64), ce.Name)
					}
				}
			case "offset_sk_buff_sock":
				if !protocolClassificationSupported {
					t.SkipNow()
				}
				off, _, err := getOffset(sk_buff.Members, "sk")
				if assert.NoError(t, err, ce.Name) {
					assert.Equal(t, uint64(off), ce.Value.(uint64), ce.Name)
				}
			case "offset_sk_buff_transport_header":
				if !protocolClassificationSupported {
					t.SkipNow()
				}
				off, _, err := getOffset(sk_buff.Members, "transport_header")
				if assert.NoError(t, err, ce.Name) {
					assert.Equal(t, uint64(off), ce.Value.(uint64), ce.Name)
				}
			case "offset_sk_buff_head":
				if !protocolClassificationSupported {
					t.SkipNow()
				}
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

func getFirstStruct(t testing.TB, btfdata *btf.Spec, name string) *btf.Struct {
	types, err := btfdata.AnyTypesByName(name)
	if err != nil {
		t.Fatalf("unable to find BTF type %s: %s", name, err)
	}
	for _, ty := range types {
		switch v := ty.(type) {
		case *btf.Struct:
			return v
		}
	}
	t.Fatalf("no matching structs named %s", name)
	return nil
}

func getFirstUnion(t testing.TB, btfdata *btf.Spec, name string) *btf.Union {
	types, err := btfdata.AnyTypesByName(name)
	if err != nil {
		t.Fatalf("unable to find BTF type %s: %s", name, err)
	}
	for _, ty := range types {
		switch v := ty.(type) {
		case *btf.Union:
			return v
		}
	}
	t.Fatalf("no matching unions named %s", name)
	return nil
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
