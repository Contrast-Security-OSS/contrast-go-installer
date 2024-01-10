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
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
)

// version describes an available version; handles strings like 'latest' or '1.2.3'.
type version struct {
	str             string
	maj, min, patch int
}

// Greater returns true if v is greater than w
func (v *version) Greater(w *version) bool {
	vslen, wslen := len(v.str) > 0, len(w.str) > 0
	if vslen && wslen {
		return v.str < w.str
	}
	if vslen {
		return true
	}
	if wslen {
		return false
	}
	//converts major/minor/patch to an int for comparison. assumes none of them will exceed 255.
	toint := func(x *version) int { return x.maj<<16 + x.min<<8 + x.patch }
	return toint(v) > toint(w)
}

func (v *version) String() string {
	if len(v.str) > 0 {
		return v.str
	}
	return fmt.Sprintf("%d.%d.%d", v.maj, v.min, v.patch)
}

func (v *version) Equal(w *version) bool {
	return v.str == w.str &&
		v.maj == w.maj &&
		v.min == w.min &&
		v.patch == w.patch
}

// convert a string to type version, which allows comparison, sorting, etc
func toVersion(s string) (v version) {
	var maj, min, patch uint64
	var err error
	if elems := strings.Split(s, "."); len(elems) == 3 {
		maj, err = strconv.ParseUint(elems[0], 10, 8)
		if err == nil {
			min, err = strconv.ParseUint(elems[1], 10, 8)
		}
		if err == nil {
			patch, err = strconv.ParseUint(elems[2], 10, 8)
		}
		if err == nil {
			v.maj, v.min, v.patch = int(maj), int(min), int(patch)
			return
		}
	}
	v.str = s
	return
}

type versions []version

func (a versions) Len() int           { return len(a) }
func (a versions) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a versions) Less(i, j int) bool { return a[i].Greater(&a[j]) } // reversed - sorts descending, alpha then numeric.

func (a versions) String() string {
	s := []string{}
	for _, v := range a {
		s = append(s, v.String())
	}
	return strings.Join(s, ", ")
}

type ErrBadVersion struct {
	AvailableVersions versions
	BadVersion        string
}

const maxVersionsListed = 5

func (err *ErrBadVersion) Error() string {
	sort.Sort(err.AvailableVersions)
	if len(err.AvailableVersions) > maxVersionsListed {
		err.AvailableVersions = err.AvailableVersions[:maxVersionsListed]
	}
	return fmt.Sprintf("Version %q does not exist. Available versions include\n\t%s\n%s",
		err.BadVersion, err.AvailableVersions.String(), agentArchivePg)
}

// reads html from body, returning extracted versions
func listVersions(body io.Reader) (versions, error) {
	var vers versions
	subdirs, err := htmlDir(body)
	if err != nil {
		return nil, err
	}
	for _, sub := range subdirs {
		vers = append(vers, toVersion(sub))
	}
	return vers, nil
}

// reads html from body, returning extracted dir links
func htmlDir(body io.Reader) ([]string, error) {
	var subdirs []string
	z := html.NewTokenizer(body)
	for {
		switch z.Next() {
		case html.ErrorToken:
			err := z.Err()
			if err == io.EOF {
				//reached end of input
				return subdirs, nil
			}
			return nil, fmt.Errorf("Dir specified does not exist. %s", agentArchivePg)
		case html.StartTagToken:
			if tok := z.Token(); tok.DataAtom == atom.A {
				for _, a := range tok.Attr {
					if a.Key == "href" {
						v := strings.TrimSuffix(a.Val, "/")
						// a link to a version will have one slash, which we already removed - skip anything else
						if strings.Count(v, "/") == 0 {
							subdirs = append(subdirs, v)
						}
					}
				}
			}
		}
	}
}
