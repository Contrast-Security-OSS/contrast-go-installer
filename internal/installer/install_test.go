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

package installer

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const dlsite = "https://pkg.contrastsecurity.com/go-agent-release"

func Test_userAgent(t *testing.T) {
	t.Run("test user agent", func(t *testing.T) {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("some data"))
		}))
		t.Cleanup(s.Close)
		response, err := makeRequest(http.MethodGet, s.URL)

		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}

		if !strings.Contains(response.Request.Header.Get("User-agent"), "contrast-go-installer") {
			t.Fatalf("expected constrast-go-install in user-agent header, got: %v", response.Request.Header.Get("User-agent"))
		}
	})
}

func Test_download(t *testing.T) {
	checksumHandler := func(b []byte) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := sha256.New()
			if _, err := io.Copy(h, bytes.NewBuffer(b)); err != nil {
				t.Fatalf("unable to calculate checksum: %s", err)
			}
			hash := hex.EncodeToString(h.Sum(nil))
			w.Header().Set("X-Checksum-Sha256", hash)
		})
	}
	var tests = map[string]struct {
		handler     http.Handler
		headHandler http.Handler

		// if non-nil, is called to configure the server
		server func(*httptest.Server) *httptest.Server

		// if non-empty, expect an error containing the string
		expectErr string
	}{
		"simple": {
			handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte("some data"))
			}),
			headHandler: checksumHandler([]byte("some data")),
		},
		"404": {
			handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(404)
			}),
			headHandler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(404)
			}),
			expectErr: `Version "v" does not exist. For a full list of versions, see`,
		},
		"500": {
			handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(500)
			}),
			headHandler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(500)
			}),
			expectErr: "server did not return 200",
		},
		"EOF from content-length mismatch": {
			handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Length", "1000")
				w.WriteHeader(200)
				_, _ = w.Write([]byte("not 1000 bytes"))
			}),
			headHandler: checksumHandler([]byte("not 1000 bytes")),
			expectErr:   "couldn't download file",
		},
		"bad connection": {
			handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte("some data"))
			}),
			server: func(s *httptest.Server) *httptest.Server {
				s.Close()
				return s
			},
			headHandler: checksumHandler([]byte("some data")),
			expectErr:   "there is a network communication issue",
		},
		"untrusted cert": {
			handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte("some data"))
			}),
			server: func(s *httptest.Server) *httptest.Server {
				return httptest.NewTLSServer(s.Config.Handler)
			},
			headHandler: checksumHandler([]byte("some data")),
			expectErr:   "certificate",
		},
		"follows redirect": {
			handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !strings.Contains(r.RequestURI, "redirect") {
					http.Redirect(w, r, "/redirect", http.StatusMovedPermanently)
					return
				}
				_, _ = w.Write([]byte("some data"))
			}),
			headHandler: checksumHandler([]byte("some data")),
		},
		"follows redirect to error": {
			handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !strings.Contains(r.RequestURI, "redirect") {
					http.Redirect(w, r, "/redirect", http.StatusMovedPermanently)
					return
				}
				w.WriteHeader(404)
			}),
			headHandler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(404)
			}),
			expectErr: `Version "v" does not exist. For a full list of versions, see`,
		},
		"url is correctly formatted": {
			handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.RequestURI == "/v/os-arch/contrast-go" {
					_, _ = w.Write([]byte("ok"))
					return
				}
				w.WriteHeader(404)
			}),
			headHandler: checksumHandler([]byte("ok")),
		},
		"lists available versions when given version is not available": {
			handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.Contains(r.RequestURI, "/v") {
					w.WriteHeader(404)
					return
				}
				_, _ = w.Write([]byte(`<html><body><a href="0.1.2/">0.1.2</a><a href="1.2.3/">1.2.3</a><a href="latest/">latest</a></body></html>`))
			}),
			headHandler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.Contains(r.RequestURI, "/v") {
					w.WriteHeader(404)
					return
				}
				checksumHandler([]byte(`<html><body><a href="0.1.2/">0.1.2</a><a href="1.2.3/">1.2.3</a><a href="latest/">latest</a></body></html>`)).ServeHTTP(w, r)
			}),
			expectErr: "\"v\" does not exist. Available versions include\n\tlatest, 1.2.3, 0.1.2",
		},
		"invalid checksum": {
			handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte("some data"))
			}),
			headHandler: checksumHandler([]byte("different data")),
			expectErr:   "checksum mismatch, expected",
		},
	}

	handler := func(handler, headHandler http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodHead && headHandler != nil {
				headHandler.ServeHTTP(w, r)
				return
			}
			handler.ServeHTTP(w, r)
		})
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			s := httptest.NewServer(handler(test.handler, test.headHandler))
			if test.server != nil {
				s = test.server(s)
			}
			t.Cleanup(s.Close)
			id := installData{
				baseURL: s.URL,
				version: "v",
				os:      "os",
				arch:    "arch",
				tmpdir:  t.TempDir(),
			}
			_, err := id.download()
			switch {
			case (test.expectErr == "") != (err == nil):
				t.Fatalf("unexpected err: %v", err)

			case test.expectErr != "":
				if !strings.Contains(err.Error(), test.expectErr) {
					t.Fatalf(
						"error did not contain expected string %q:\n%v",
						test.expectErr, err,
					)
				}
			}
		})
	}
}

func Test_install(t *testing.T) {
	var tests = map[string]struct {
		tmpPresent bool

		// if the handler lets the file download, save it to this path in a tmp
		// dir; defaults to "contrast-go"
		dst string

		expectErr string

		expectNotExist bool

		lookupFunc func() (string, error)
	}{
		"basic": {
			tmpPresent: true,
		},
		"missing dir": {
			tmpPresent: true,
			dst:        filepath.Join(t.TempDir(), "dir", "contrast-go"),
		},
		"missing": {
			tmpPresent:     false,
			expectErr:      "no such file",
			expectNotExist: true,
		},
		"unwriteable dir": {
			dst:            filepath.Join("dir", "contrast-go"),
			expectErr:      "rename",
			expectNotExist: true,
		},
		"inaccessible": {
			tmpPresent:     true,
			expectErr:      "not found in $PATH",
			expectNotExist: false,
			lookupFunc: func() (string, error) {
				return "", fmt.Errorf("not found in path")
			},
		},
		"shadowed": {
			tmpPresent:     true,
			expectErr:      "shadowed in path",
			expectNotExist: false,
			lookupFunc: func() (string, error) {
				return "/made/up/directory", nil
			},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			tmp := t.TempDir() + "/tmpfile"
			id := installData{
				dst: test.dst,
			}
			if len(id.dst) == 0 {
				id.dst = t.TempDir() + "/contrast-go"
			}
			if test.tmpPresent {
				if err := os.WriteFile(tmp, []byte(t.Name()), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if test.lookupFunc == nil {
				test.lookupFunc = func() (string, error) {
					return id.dst, nil
				}
			}
			err := id.install(tmp, test.lookupFunc)
			switch {
			case (test.expectErr == "") != (err == nil):
				t.Fatalf("unexpected err: %v", err)

			case test.expectErr != "":
				if !strings.Contains(err.Error(), test.expectErr) {
					t.Fatalf(
						"error did not contain expected string %q:\n%v",
						test.expectErr, err,
					)
				}
			}
			fi, err := os.Stat(id.dst)
			if test.expectNotExist {
				if !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("expected file to not exist")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}

			if fi.Size() < 1 {
				t.Fatal("unexpected 0 length file")
			}

			if fi.Mode()&0100 == 0 {
				t.Fatalf("file with mode %v is not executable", fi.Mode())
			}
		})
	}
}
