// Copyright 2024 Contrast Security, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLicense(t *testing.T) {
	licenseRaw, err := os.ReadFile("LICENSE")
	if err != nil {
		t.Fatalf("failed to read LICENSE: %v", err)
	}

	licenseLines := strings.Split(string(licenseRaw), "\n")

	expectedFirstLine := fmt.Sprintf("Copyright %d Contrast Security, Inc.", time.Now().Year())
	if licenseLines[0] != expectedFirstLine {
		t.Fatalf("incorrect first line of LICENSE (got %q, want %q)", licenseLines[0], expectedFirstLine)
	}

	var sb strings.Builder

	// license is 13 lines long and this won't change so hardcode it
	for i := 0; i < 13; i++ {
		ll := licenseLines[i]
		sb.WriteString("//")
		if ll != "" {
			sb.WriteByte(' ')
		}
		sb.WriteString(ll)
		sb.WriteByte('\n')
	}
	expectedLicenseHeader := sb.String()
	t.Logf("expected license header:\n%s\n raw: %q", expectedLicenseHeader, expectedLicenseHeader)

	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if !strings.HasSuffix(path, ".go") {
			// skip non-Go files
			return nil
		}

		relPath, err := filepath.Rel(dir, path)
		if err != nil {
			t.Fatal(err)
		}
		t.Run("Headers/"+relPath, func(t *testing.T) {
			f, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()

			licenseSize := len(expectedLicenseHeader)
			buf := make([]byte, licenseSize)
			n, err := f.Read(buf)
			if err != nil {
				t.Fatalf("failed to read file: %v", err)
			}
			head := string(buf[:n])
			t.Logf("head:\n%s\n\n raw: %q", head, head)
			if n != licenseSize || !strings.HasPrefix(head, "// Copyright") {
				t.Fatalf("missing license header")
			}
			if head != expectedLicenseHeader {
				t.Fatal("invalid license header")
			}
		})

		return nil
	})
}
