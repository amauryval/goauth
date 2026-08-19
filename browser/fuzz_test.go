package browser

import (
	"testing"
)

// FuzzSealerOpen throws arbitrary cookie values at the sealer.
//
// A cookie value is attacker controlled: whatever a browser is handed can come back changed. The
// property under test is that nothing but a value this server sealed ever opens, and that nothing
// panics on the way — a crash in this path would be a denial of service reachable without any
// credential at all.
func FuzzSealerOpen(f *testing.F) {
	sealer, err := newSealer([]byte(testSecret))
	if err != nil {
		f.Fatal(err)
	}

	sealed, err := sealer.seal(sessionPurpose, []byte(`{"a":"an-access-token"}`))
	if err != nil {
		f.Fatal(err)
	}

	f.Add(sealed)
	f.Add("")
	f.Add("not base64 !!")
	f.Add("AAAAAAAAAAAAAAAA")
	f.Add(sealed[:len(sealed)/2])

	// A fuzz corpus keeps what earlier runs found, genuine sealed values among them, so "this did
	// not open" is not a property that can be asserted here. What can: an open never panics, a
	// failure yields nothing, and anything that does open was sealed for this purpose and reseals
	// to a value that opens to the very same bytes.
	f.Fuzz(func(t *testing.T, value string) {
		opened, err := sealer.open(sessionPurpose, value)
		if err != nil {
			if opened != nil {
				t.Fatalf("a failed open returned %q", opened)
			}

			return
		}

		if _, err := sealer.open(pendingPurpose, value); err == nil {
			t.Fatalf("a value opened under both purposes: %q", value)
		}

		resealed, err := sealer.seal(sessionPurpose, opened)
		if err != nil {
			t.Fatal(err)
		}

		again, err := sealer.open(sessionPurpose, resealed)
		if err != nil {
			t.Fatalf("what this server sealed did not open again: %v", err)
		}

		if string(again) != string(opened) {
			t.Fatalf("a round trip changed the payload: %q became %q", opened, again)
		}
	})
}

// FuzzIsLocalPath throws arbitrary redirect targets at the open redirect check.
//
// The property is that anything accepted keeps the browser on this application: no scheme, no
// host, and no leading "//" or backslash a browser would read as one.
func FuzzIsLocalPath(f *testing.F) {
	for _, seed := range []string{
		"/", "/skills", "/skills?tab=all", "//evil.example.com", `/\evil.example.com`,
		"https://evil.example.com", "javascript:alert(1)", "", "/..//evil.example.com",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, path string) {
		if !isLocalPath(path) {
			return
		}

		if len(path) == 0 || path[0] != '/' {
			t.Fatalf("accepted a target that is not a path: %q", path)
		}

		if len(path) > 1 && (path[1] == '/' || path[1] == '\\') {
			t.Fatalf("accepted a target a browser reads as another host: %q", path)
		}

		for _, character := range path {
			if character == '\\' {
				t.Fatalf("accepted a target carrying a backslash: %q", path)
			}
		}
	})
}
