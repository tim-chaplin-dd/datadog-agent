// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf
// +build linux_bpf

package kprobe

import (
	"path/filepath"
	"os"

	"github.com/cilium/ebpf/btf"

	"github.com/DataDog/datadog-agent/pkg/metadata/host"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

func getBTF(userProvidedBtfPath, collectionPath string) *btf.Spec {
	var btfSpec *btf.Spec
	var err error

	if userProvidedBtfPath != "" {
		btfSpec, err = loadBTFFrom(userProvidedBtfPath)
		if err == nil {
			log.Debugf("loaded BTF from %s", userProvidedBtfPath)
			return btfSpec
		}

		log.Warnf("couldn't load BTF from %s: %s", userProvidedBtfPath, err)
	}

	btfSpec, err = checkEmbeddedCollection(collectionPath)
	if err == nil {
		log.Debugf("loaded BTF from embedded collection")
		return btfSpec
	}
	log.Debugf("couldn't find BTF in embedded collection: %s", err)

	btfSpec, err = btf.LoadKernelSpec() 
	if err == nil {
		log.Debugf("loaded BTF from default kernel location")
		return btfSpec
	}
	log.Debugf("couldn't find BTF in default kernel locations: %s", err)

	return nil
}

func checkEmbeddedCollection(collectionPath string) (*btf.Spec, error) {
	si := host.GetStatusInformation()
	platform := si.Platform
	kernelVersion := si.KernelVersion

	path := filepath.Join(collectionPath, platform, "/", kernelVersion + ".btf")
	log.Debugf("checking embedded collection for btf at %s", path)

	/*
	Note: for the purposes of this POC the embedded BTFs aren't minimized or compressed
	*/

	return loadBTFFrom(path)
}

func loadBTFFrom(path string) (*btf.Spec, error) {
	data, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	
	return btf.LoadSpecFromReader(data)
}
