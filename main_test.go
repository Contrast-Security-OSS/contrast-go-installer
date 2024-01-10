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
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rogpeppe/go-internal/testscript"
)

func TestMain(m *testing.M) {
	os.Exit(testscript.RunMain(m, map[string]func() int{
		"contrast-go-installer": main1,
	}))
}

// replacePath replaces the old location with the new location in $PATH
func replacePath(path, old, new string) string {
	newpath := []string{}
	for _, filepath := range strings.Split(path, ":") {
		if filepath == old {
			newpath = append(newpath, new)
		} else {
			newpath = append(newpath, filepath)
		}
	}
	return strings.Join(newpath, ":")
}

func TestScripts(t *testing.T) {
	testscript.Run(t, testscript.Params{
		Dir: "testdata",
		Setup: func(env *testscript.Env) error {
			bin := filepath.Join(env.WorkDir, "bin")
			if err := os.Mkdir(filepath.Join(env.WorkDir, "bin"), 0700); err != nil {
				env.T().Fatal(err)
			}

			// go env GOBIN
			installedGo, err := exec.LookPath("go")
			if err != nil {
				env.T().Fatal(err)
			}
			cmd := exec.Command(installedGo, "env", "GOBIN")
			var stdout bytes.Buffer
			cmd.Stdout = &stdout
			if err := cmd.Run(); err != nil {
				env.T().Fatal(err)
			}
			out := strings.Fields(stdout.String())
			if len(out) > 0 {
				// Remove previous GOBIN from $PATH, and add the new GOBIN
				// to avoid shadowing contrast-go if it is already installed
				// on your machine
				env.Setenv("PATH", replacePath(env.Getenv("PATH"), out[0], bin))
			} else {
				// If GOBIN unset, no need to replace it in PATH
				env.Setenv("PATH", env.Getenv("PATH")+":"+bin)
			}

			env.Setenv("GOBIN", bin)

			return nil
		},
		Cmds: map[string]func(*testscript.TestScript, bool, []string){
			"run-test-server": startServer,
		},
		Condition: func(cond string) (bool, error) {
			switch cond {
			case "real":
				return false, nil
			}

			return false, errors.New("unrecognized condition")
		},
	})
}

const (
	versdir = `<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<html><body><h1>Index of go-agent-release/</h1>
<pre>Name    Last modified      Size</pre><hr/>
<pre><a href="1.2.3/">1.2.3/</a>  26-Feb-2021 22:24    -
<a href="3.0.0/">3.0.0/</a>   07-Jul-2022 15:47    -
<a href="latest/">latest/</a>  22-Feb-2021 15:28    -
</pre><hr/><address style="font-size:small;">Online Server</address></body></html>`

	archdir = `<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<html><body><h1>Index of go-agent-release/3.0.0</h1>
<pre>Name              Last modified      Size</pre><hr/>
<pre><a href="../">../</a>
<a href="darwin-amd64/">darwin-amd64/</a>      07-Jul-2022 15:47    -
<a href="darwin-arm64/">darwin-arm64/</a>      07-Jul-2022 15:47    -
<a href="linux-amd64/">linux-amd64/</a>       07-Jul-2022 15:47    -
<a href="dependencies.csv">dependencies.csv</a>   07-Jul-2022 15:47  1.25 KB
</pre><hr/><address style="font-size:small;">Online Server</address></body></html>`

	archdirNoArm = `<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<html><body><h1>Index of go-agent-release/1.2.3</h1>
<pre>Name              Last modified      Size</pre><hr/>
<pre><a href="../">../</a>
<a href="darwin-amd64/">darwin-amd64/</a>      07-Jul-2022 15:47    -
<a href="linux-amd64/">linux-amd64/</a>       07-Jul-2022 15:47    -
<a href="dependencies.csv">dependencies.csv</a>   07-Jul-2022 15:47  1.25 KB
</pre><hr/><address style="font-size:small;">Online Server</address></body></html>`
)

var (
	allowedOses   = []string{"linux", "darwin"}
	allowedArches = []string{"amd64", "arm64"}
)

func allowed(list []string, val string) bool {
	for _, elem := range list {
		if val == elem {
			return true
		}
	}
	return false
}

// startServer starts a test server to handle downloads and puts the server's
// address in the $baseURL environment variable.
func startServer(ts *testscript.TestScript, neg bool, args []string) {
	srvHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if neg {
			w.WriteHeader(404)
			return
		}
		paths := strings.Split(r.RequestURI[1:], "/")
		switch len(paths) {
		case 0:
			_, _ = w.Write([]byte(versdir))
		case 1:
			switch paths[0] {
			case "latest":
				http.Redirect(w, r, "../3.0.0", http.StatusSeeOther)
				return
			case "3.0.0":
				_, _ = w.Write([]byte(archdir))
			case "1.2.3":
				_, _ = w.Write([]byte(archdirNoArm))
			default:
				w.WriteHeader(404)
			}
			//case 2:
			// this would be the dir containing contrast-go, but we don't read it. handled by default case.
		case 3:
			osArch := strings.Split(paths[1], "-")
			if len(osArch) != 2 {
				w.WriteHeader(404)
				return
			}
			arches := allowedArches
			if paths[0] != "latest" && paths[0] != "3.0.0" {
				// only later revisions have native arm64 binaries
				arches = []string{"amd64"}
			}

			if !allowed(arches, osArch[1]) {
				w.WriteHeader(404)
				return
			}
			if !allowed(allowedOses, osArch[0]) {
				w.WriteHeader(404)
				return
			}
			if paths[2] == "contrast-go" {
				_, _ = w.Write([]byte(r.RequestURI))
			} else {
				w.WriteHeader(404)
			}
		default:
			ts.Fatalf("unexpected request for %s\n", r.RequestURI)
		}
	})
	headHandler := func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodHead {
				h := sha256.New()
				_, err := io.Copy(h, bytes.NewBufferString(r.RequestURI))
				if err != nil {
					ts.Fatalf("unable to calculate checksum: %s", err)
				}
				hash := hex.EncodeToString(h.Sum(nil))
				w.Header().Set("X-Checksum-sha256", hash)
			}
			h.ServeHTTP(w, r)
		})
	}
	s := httptest.NewServer(headHandler(srvHandler))
	ts.Defer(s.Close)
	ts.Logf("test server listening at: %s", s.URL)

	ts.Setenv("baseURL", s.URL)
}
