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
	"net/http"
	"strings"
	"testing"
)

func Test_listVersions(t *testing.T) {
	t.Run("correctly parses versions", func(t *testing.T) {
		htm := []byte(`<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<html><title>Index of go-agent-release/</title></head>
<body><h1>Index of go-agent-release/</h1>
<pre>Name    Last modified      Size</pre><hr/>
<pre><a href="0.10.0/">0.10.0/</a>  26-Feb-2021 22:24    -
<a href="0.11.0/">0.11.0/</a>  09-Mar-2021 17:35    -
<a href="0.12.0/">0.12.0/</a>  16-Mar-2021 16:22    -
<a href="3.0.0/">3.0.0/</a>   07-Jul-2022 15:47    -
<a href="latest/">latest/</a>  22-Feb-2021 15:28    -
<a href="/path/to/something/else/">something else</a>
</pre>
<hr/><address style="font-size:small;">Artifactory Online Server</address></body></html>`)

		var want versions
		for _, v := range []string{"0.10.0", "0.11.0", "0.12.0", "3.0.0", "latest"} {
			want = append(want, toVersion(v))
		}

		buf := bytes.NewReader(htm)
		got, err := listVersions(buf)
		if err != nil {
			t.Errorf("listVersions() error = %v", err)
		}
		if len(want) != len(got) {
			t.Errorf("want %d versions, got %d", len(want), len(got))
		}
		for i := range want {
			if len(got) < i+1 {
				break
			}
			if !want[i].Equal(&got[i]) {
				t.Errorf("mismatch: want[%d]==%q, got[%d]==%q", i, want[i], i, got[i])
			}
		}

		if t.Failed() {
			t.Logf("\nwant: %#v\n got: %#v", want, got)
		}
	})
	t.Run("versions pseudo-dir is parseable", func(t *testing.T) {
		resp, err := http.Get(dlsite)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("unexpected http response %s from %s", resp.Status, resp.Request.URL)
		}
		got, err := listVersions(resp.Body)
		if err != nil {
			t.Error(err)
		}
		var want versions
		for _, v := range []string{"3.0.0", "latest"} { // will any versions ever be removed?
			want = append(want, toVersion(v))
		}
		for _, g := range got {
			for i := 0; i < len(want); i++ {
				if g == want[i] {
					want = append(want[:i], want[i+1:]...)
				}
			}
		}
		if len(want) != 0 {
			t.Errorf("got %#v\nwhich is missing %#v", got, want)
		}
	})
}

func TestErrBadVersion_Error(t *testing.T) {
	// ensures returned versions are sorted with 'latest' first, then numeric versions descending
	want := "latest, 3.0.0, 1.12.3, 1.2.3, 0.12.0"
	var avail versions
	for _, v := range []string{"0.10.0", "1.12.3", "0.11.0", "0.12.0", "3.0.0", "latest", "1.2.3"} {
		avail = append(avail, toVersion(v))
	}

	err := &ErrBadVersion{
		AvailableVersions: avail,
		BadVersion:        "badVer",
	}
	got := err.Error()
	if !strings.Contains(got, want) {
		t.Errorf("\nwant %s\n got %s", want, got)
	}
}

func TestVersion_Equal(t *testing.T) {
	numeric := version{maj: 1, min: 2, patch: 3}
	str := version{str: "vers"}

	tests := []struct {
		name     string
		lhs, rhs version
		want     bool
	}{
		{
			name: "string equal",
			lhs:  str,
			rhs:  str,
			want: true,
		},
		{
			name: "string inequal",
			lhs:  version{},
			rhs:  str,
			want: false,
		},
		{
			name: "numeric equal",
			lhs:  numeric,
			rhs:  numeric,
			want: true,
		},
		{
			name: "numeric inequal maj",
			lhs:  numeric,
			rhs:  version{maj: numeric.maj + 1, min: numeric.min, patch: numeric.patch},
			want: false,
		},
		{
			name: "numeric inequal min",
			lhs:  numeric,
			rhs:  version{maj: numeric.maj, min: numeric.min + 1, patch: numeric.patch},
			want: false,
		},
		{
			name: "numeric inequal patch",
			lhs:  numeric,
			rhs:  version{maj: numeric.maj, min: numeric.min, patch: numeric.patch + 1},
			want: false,
		},
	}
	for _, td := range tests {
		t.Run(td.name, func(t *testing.T) {
			got := td.lhs.Equal(&td.rhs)
			if got != td.want {
				t.Errorf("want %t got %t for lhs=%#v\nrhs=%#v", td.want, got, td.lhs, td.rhs)
			}
		})
	}
}

func TestVersion_Greater(t *testing.T) {
	numeric := version{maj: 1, min: 2, patch: 3}
	str := version{str: "vers"}

	tests := []struct {
		name     string
		lhs, rhs version
		want     bool
	}{
		{
			name: "string equal",
			lhs:  str,
			rhs:  str,
			want: false,
		},
		{
			name: "string empty",
			lhs:  version{},
			rhs:  str,
			want: false,
		},
		{
			name: "string greater",
			lhs:  version{str: "aaa"},
			rhs:  str,
			want: true,
		},
		{
			name: "string less",
			lhs:  version{str: "xxx"},
			rhs:  str,
			want: false,
		},
		{
			name: "numeric equal",
			lhs:  numeric,
			rhs:  numeric,
			want: false,
		},
		{
			name: "numeric lt maj",
			lhs:  numeric,
			rhs:  version{maj: numeric.maj + 1, min: numeric.min, patch: numeric.patch},
			want: false,
		},
		{
			name: "numeric lt min",
			lhs:  numeric,
			rhs:  version{maj: numeric.maj, min: numeric.min + 1, patch: numeric.patch},
			want: false,
		},
		{
			name: "numeric lt patch",
			lhs:  numeric,
			rhs:  version{maj: numeric.maj, min: numeric.min, patch: numeric.patch + 1},
			want: false,
		},
		{
			name: "numeric gt maj",
			lhs:  numeric,
			rhs:  version{maj: numeric.maj - 1, min: numeric.min, patch: numeric.patch},
			want: true,
		},
		{
			name: "numeric gt min",
			lhs:  numeric,
			rhs:  version{maj: numeric.maj, min: numeric.min - 1, patch: numeric.patch},
			want: true,
		},
		{
			name: "numeric gt patch",
			lhs:  numeric,
			rhs:  version{maj: numeric.maj, min: numeric.min, patch: numeric.patch - 1},
			want: true,
		},
	}
	for _, td := range tests {
		t.Run(td.name, func(t *testing.T) {
			got := td.lhs.Greater(&td.rhs)
			if got != td.want {
				t.Errorf("want %t got %t for\nlhs=%#v\nrhs=%#v", td.want, got, td.lhs, td.rhs)
			}
		})
	}
}

func Test_toVersion(t *testing.T) {
	tests := []struct {
		name  string
		in    string
		wantV version
	}{
		{
			name:  "semver",
			in:    "1.2.3",
			wantV: version{maj: 1, min: 2, patch: 3},
		},
		{
			name:  "too many dots",
			in:    "1.2.3.",
			wantV: version{str: "1.2.3."},
		},
		{
			name:  "too few dots",
			in:    "1.23",
			wantV: version{str: "1.23"},
		},
		{
			name:  "empty",
			in:    "",
			wantV: version{},
		},
		{
			name:  "string",
			in:    "latest",
			wantV: version{str: "latest"},
		},
		{
			name:  "dots but not numeric",
			in:    "1.a.5",
			wantV: version{str: "1.a.5"},
		},
	}
	for _, td := range tests {
		t.Run(td.name, func(t *testing.T) {
			gotV := toVersion(td.in)
			if !gotV.Equal(&td.wantV) {
				t.Errorf("\nwant %#v\n got %#v", td.wantV, gotV)
			}
		})
	}
}
