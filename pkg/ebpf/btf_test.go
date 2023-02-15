// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package ebpf

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBTFExtraction(t *testing.T) {
	tests := map[string]string{
		"ubuntu/20.04": "5.4.0-1010-azure",
		"debian":       "4.19.0-21-arm64",
	}
	for sub, base := range tests {
		t.Run(sub, func(t *testing.T) {
			tmpdir := t.TempDir()

			srcpath := filepath.Join(".", "testdata", "minimized-btfs.tar.xz")
			srcf, err := os.Open(srcpath)
			require.NoError(t, err)
			t.Cleanup(func() { srcf.Close() })

			dstpath := filepath.Join(tmpdir, "minimized-btfs.tar.xz")
			dstf, err := os.Create(dstpath)
			require.NoError(t, err)
			t.Cleanup(func() { dstf.Close() })

			_, err = io.Copy(dstf, srcf)
			require.NoError(t, err)
			dstf.Close()
			srcf.Close()

			spec, err := extractFromEmbeddedCollection(dstpath, sub, base)
			require.NoError(t, err)
			require.NotNil(t, spec)
		})
	}
}
