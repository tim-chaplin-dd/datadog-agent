// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf
// +build linux_bpf

package ebpf

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/DataDog/gopsutil/host"
	"github.com/cilium/ebpf/btf"
	"github.com/mholt/archiver/v3"

	"github.com/DataDog/datadog-agent/pkg/util/log"
)

func GetBTF(userProvidedBtfPath string, bpfDir string, collectionFilePath string) (*btf.Spec, COREResult) {
	var btfSpec *btf.Spec
	var err error

	if userProvidedBtfPath != "" {
		btfSpec, err = loadBTFFrom(userProvidedBtfPath)
		if err == nil {
			log.Debugf("loaded BTF from %s", userProvidedBtfPath)
			return btfSpec, successCustomBTF
		}
	}

	btfSpec, err = checkEmbeddedCollection(filepath.Join(bpfDir, collectionFilePath))
	if err == nil {
		log.Debugf("loaded BTF from embedded collection")
		return btfSpec, successEmbeddedBTF
	}
	log.Debugf("couldn't find BTF in embedded collection: %s", err)

	btfSpec, err = btf.LoadKernelSpec()
	if err == nil {
		log.Debugf("loaded BTF from default kernel location")
		return btfSpec, successDefaultBTF
	}
	log.Debugf("couldn't find BTF in default kernel locations: %s", err)

	return nil, btfNotFound
}

func getBTFDirAndFilename() (dir, file string, err error) {
	info, err := host.Info()
	if err != nil {
		return "", "", fmt.Errorf("failed to retrieve host info: %s", err)
	}

	platform := info.Platform
	platformVersion := info.PlatformVersion
	kernelVersion := info.KernelVersion

	// using directory names from .gitlab/deps_build.yml
	switch platform {
	case "amzn", "amazon":
		return "amazon", kernelVersion, nil
	case "suse", "sles": //opensuse treated differently on purpose
		return "sles", kernelVersion, nil
	case "redhat", "rhel":
		return "redhat", kernelVersion, nil
	case "oracle", "ol":
		return "oracle", kernelVersion, nil
	case "ubuntu":
		// Ubuntu BTFs are stored in subdirectories corresponding to platform version.
		// This is because we have BTFs for different versions of ubuntu with the exact same
		// kernel name, so kernel name alone is not a unique identifier.
		return filepath.Join(platform, platformVersion), kernelVersion, nil
	default:
		return platform, kernelVersion, nil
	}
}

func checkEmbeddedCollection(collectionTarball string) (*btf.Spec, error) {
	btfSubdirectory, btfBasename, err := getBTFDirAndFilename()
	if err != nil {
		return nil, err
	}
	return extractFromEmbeddedCollection(collectionTarball, btfSubdirectory, btfBasename)
}

func extractFromEmbeddedCollection(collectionTarball string, btfSubdirectory string, btfBasename string) (*btf.Spec, error) {
	collectionPath := filepath.Dir(collectionTarball)
	btfFilename := btfBasename + ".btf"
	btfTarballFilename := btfBasename + ".btf.tar.xz"
	destinationFolder := filepath.Join(collectionPath, btfSubdirectory)
	extractedBtfPath := filepath.Join(destinationFolder, btfFilename)

	// If we've previously extracted the BTF file in question, we can just load it
	if _, err := os.Stat(extractedBtfPath); err == nil {
		log.Debugf("loading BTF from %s", extractedBtfPath)
		return loadBTFFrom(extractedBtfPath)
	}
	log.Debugf("%s not found, obtaining from archive", extractedBtfPath)

	// The embedded BTFs are compressed twice: the individual BTFs themselves are compressed, and the collection
	// of BTFs as a whole is also compressed.
	// This means that we'll need to first extract the specific BTF which  we're looking for from the collection
	// tarball, and then unarchive it.
	btfTarball := filepath.Join(destinationFolder, btfTarballFilename)
	if _, err := os.Stat(btfTarball); errors.Is(err, fs.ErrNotExist) {
		targetBtfFile := filepath.Join(btfSubdirectory, btfTarballFilename)
		log.Debugf("%s not found, extracting from archive", btfTarball)
		if err := archiver.NewTarXz().Extract(collectionTarball, targetBtfFile, collectionPath); err != nil {
			return nil, fmt.Errorf("extract single kernel .btf.tar.xz: %w", err)
		}
	}

	log.Debugf("unarchiving %s to %s", btfTarball, destinationFolder)
	if err := archiver.NewTarXz().Unarchive(btfTarball, destinationFolder); err != nil {
		return nil, fmt.Errorf("unarchive single kernel .btf: %w", err)
	}
	log.Debugf("loading BTF from %s", extractedBtfPath)
	return loadBTFFrom(extractedBtfPath)
}

func loadBTFFrom(path string) (*btf.Spec, error) {
	data, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer data.Close()

	return btf.LoadSpecFromReader(data)
}
