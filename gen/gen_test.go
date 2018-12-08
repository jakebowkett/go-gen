package gen

import (
	"regexp"
	"strings"
	"testing"
)

func TestCrypto128(t *testing.T) {
	got, err := Crypto128()
	testCryptoN(t, 128, 172, got, err)
}

func TestCrypto256(t *testing.T) {
	got, err := Crypto256()
	testCryptoN(t, 256, 344, got, err)
}

func testCryptoN(t *testing.T, bytes int, wantLen int, got string, err error) {

	pattern := `^[a-zA-Z0-9_=-]*$`
	r := regexp.MustCompile(pattern)

	if err != nil {
		t.Errorf("Crypto%d() returned error: %q", bytes, err)
		return
	}

	if len(got) != wantLen {
		t.Errorf("Crypto%d() returned string of length %d, wanted %d", bytes, len(got), wantLen)
	}

	if !r.MatchString(got) {
		t.Errorf("Crypto%d()\n"+
			"    return %q\n"+
			"    wanted %s\n",
			bytes, got, pattern)
	}
}

func TestAlpha(t *testing.T) {

	pattern := `^[a-zA-Z]*$`
	r := regexp.MustCompile(pattern)

	cases := []struct {
		n       int
		wantErr bool
	}{
		{-1, true},
		{0, false},
		{1, false},
		{5, false},
		{32, false},
		{24646, false},
	}

	for _, c := range cases {
		if got, err := Alpha(c.n); !r.MatchString(got) || c.wantErr && err == nil {
			t.Errorf("Alpha(%d) return %q, wanted %s.", c.n, got, pattern)
		}
	}
}

func TestAlphaNum(t *testing.T) {

	pattern := `^[a-zA-Z0-9]*$`
	r := regexp.MustCompile(pattern)

	cases := []struct {
		n       int
		wantErr bool
	}{
		{-1, true},
		{0, false},
		{1, false},
		{5, false},
		{32, false},
		{24646, false},
	}

	for _, c := range cases {
		if got, err := AlphaNum(c.n); !r.MatchString(got) || c.wantErr && err == nil {
			t.Errorf("AlphaNum(%d) return %q, wanted %s.", c.n, got, pattern)
		}
	}
}

func TestNum(t *testing.T) {

	pattern := `^[0-9]*$`
	r := regexp.MustCompile(pattern)

	cases := []struct {
		n       int
		wantErr bool
	}{
		{-1, true},
		{0, false},
		{1, false},
		{5, false},
		{32, false},
		{24646, false},
	}

	for _, c := range cases {
		if got, err := Num(c.n); !r.MatchString(got) || c.wantErr && err == nil {
			t.Errorf("Num(%d) return %q, wanted %s.", c.n, got, pattern)
		}
	}
}

func TestFromCharSet(t *testing.T) {

	cases := []struct {
		n       int
		charSet string
		wantErr bool
	}{
		{-1, "abcdef-=_", true}, // negative index
		{4, "世界世", true},        // duplicate
		{4, "世界地球風火災水稲妻太陽", false},
		{9, "@!$^&*()", false},
		{5, "😀😁😂🤣😄😅", false}, // emojis
		{32, "", false},
		{24646, "ab", false},
		{24646, "a", false},
	}
	for _, c := range cases {
		got, err := FromCharSet(c.n, c.charSet)
		if !charsInSet(c.charSet, got) || c.wantErr && err == nil {
			t.Errorf(
				"FromCharSet(%d) return %q, wanted string built from %q.",
				c.n, got, c.charSet)
		}
	}
}

func charsInSet(set, chars string) bool {
	cc := strings.Split(chars, "")
	for _, c := range cc {
		if !strings.Contains(set, c) {
			return false
		}
	}
	return true
}
