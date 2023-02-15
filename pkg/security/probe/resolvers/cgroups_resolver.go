// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux
// +build linux

package resolvers

import (
	"sync"

	"github.com/DataDog/datadog-agent/pkg/security/secl/model"
	"github.com/hashicorp/golang-lru/v2/simplelru"
)

// CgroupCacheEntry describes a cached cgroup
type CgroupCacheEntry struct {
	pid1         uint32
	creationTime uint64
	refCount     int
}

// GetPID1 returns the root pid of a cgroup
func (e *CgroupCacheEntry) GetPID1() uint32 {
	return e.pid1
}

// GetCreationTime returns the root pid of a cgroup
func (e *CgroupCacheEntry) GetCreationTime() uint64 {
	return e.creationTime
}

// CgroupsResolver defines a cgroup monitor
type CgroupsResolver struct {
	sync.RWMutex
	pids *simplelru.LRU[string, *CgroupCacheEntry]
}

// AddCgroup associates a container id and a pid which is expected to be the pid 1
func (cr *CgroupsResolver) AddCgroup(process *model.ProcessCacheEntry, pid uint32) {
	cr.Lock()
	defer cr.Unlock()

	entry, exists := cr.pids.Get(process.ContainerID)
	if !exists {
		cr.pids.Add(process.ContainerID, &CgroupCacheEntry{
			pid1:         pid,
			refCount:     1,
			creationTime: uint64(process.ProcessContext.ExecTime.UnixNano()),
		})
	} else {
		if entry.pid1 > pid {
			entry.pid1 = pid
		}
		entry.refCount++
	}
}

// Get returns the cgroup with specified id
func (cr *CgroupsResolver) Get(id string) (*CgroupCacheEntry, bool) {
	cr.RLock()
	defer cr.RUnlock()

	entry, exists := cr.pids.Get(id)
	if !exists {
		return nil, false
	}

	return entry, true
}

// DelByPID force removes the entry
func (cr *CgroupsResolver) DelByPID(pid uint32) {
	cr.Lock()
	defer cr.Unlock()

	for _, id := range cr.pids.Keys() {
		entry, exists := cr.pids.Get(id)
		if exists && entry.pid1 == pid {
			cr.pids.Remove(id)
			break
		}
	}
}

// Release decrement usage
func (cr *CgroupsResolver) Release(id string) {
	cr.Lock()
	defer cr.Unlock()

	entry, exists := cr.pids.Get(id)
	if exists {
		entry.refCount--
		if entry.refCount <= 0 {
			cr.pids.Remove(id)
		}
	}
}

// Len return the number of entries
func (cr *CgroupsResolver) Len() int {
	cr.RLock()
	defer cr.RUnlock()

	return cr.pids.Len()
}

// NewCgroupsResolver returns a new cgroups monitor
func NewCgroupsResolver() (*CgroupsResolver, error) {
	pids, err := simplelru.NewLRU[string, *CgroupCacheEntry](1024, nil)
	if err != nil {
		return nil, err
	}
	return &CgroupsResolver{
		pids: pids,
	}, nil
}
