// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf
// +build linux_bpf

package ebpf

import (
	"github.com/cilium/ebpf/btf"
	"github.com/mholt/archiver/v3"
	"os"

	"github.com/DataDog/datadog-agent/pkg/util/log"
)

func GetBTF(userProvidedBtfPath, collectionPath string) (*btf.Spec, error) {
	var btfSpec *btf.Spec
	var err error

	if userProvidedBtfPath != "" {
		btfSpec, err = loadBTFFrom(userProvidedBtfPath)
		if err == nil {
			log.Debugf("loaded BTF from %s", userProvidedBtfPath)
			return btfSpec, nil
		}
	}

	// TODO check this after embedded collection
	btfSpec, err = btf.LoadKernelSpec()
	if err == nil {
		log.Debugf("loaded BTF from default kernel location")
		return btfSpec, nil
	}
	log.Debugf("couldn't find BTF in default kernel locations: %s", err)
	//

	//btfSpec, err = checkEmbeddedCollection(collectionPath)
	//if err == nil {
	//	log.Debugf("loaded BTF from embedded collection")
	//	return btfSpec, nil
	//}
	//log.Debugf("couldn't find BTF in embedded collection: %s", err)

	btfSpec, _ = btf.LoadKernelSpec()
	// if err == nil {
	if btfSpec != nil {
		log.Debugf("loaded BTF from default kernel location")
		return btfSpec, nil
	}
	log.Debugf("couldn't find BTF in default kernel locations: %s", err)

	return nil, err
}

func loadBTFFrom(path string) (*btf.Spec, error) {
	// All embedded BTFs must first be decompressed
	if err := archiver.NewTarXz().Unarchive(path+".tar.xz", path); err != nil {
		return nil, err
	}

	data, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	return btf.LoadSpecFromReader(data)
}
