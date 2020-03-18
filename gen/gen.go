/*
Package gen contains functions for generating strings.
*/
package gen

import (
	crypto "crypto/rand"
	"encoding/base64"
	"errors"
	"math/rand"
	"strings"
	"sync"
	"time"
)

const (
	setBase64   = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"
	setAlphaNum = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	setAlpha    = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	setNum      = "0123456789"
)

var (
	seedMu = sync.Mutex{}
	seed   = time.Now().UnixNano()
)

/*
Crypto128 generates a 128 byte (1024 bit) cryptographically
secure token that is base 64 encoded and URL-safe. The resulting
token will have a length of 172 bytes/characters.

Returns an error if it could not read all 128 bytes.
*/
func Crypto128() (string, error) {
	return cryptoGen(128)
}

/*
Crypto256 generates a 256 byte (2048 bit) cryptographically
secure token that is base 64 encoded and URL-safe. The resulting
token will have a length of 344 bytes/characters.

Returns an error if it could not read all 256 bytes.
*/
func Crypto256() (string, error) {
	return cryptoGen(256)
}

func cryptoGen(n int) (string, error) {
	bb := make([]byte, n)
	_, err := crypto.Read(bb)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bb), nil
}

/*
Do not use for generating secure tokens! Use the Crypto*
functions instead.

Alpha generates a pseudo-random alpha string containing length
number of characters. It uses the characters A-Z and a-z.

Returns an error if n is negative.
*/
func Alpha(length int) (string, error) {
	return FromCharSet(length, setAlpha)
}

/*
Do not use for generating secure tokens! Use the Crypto*
functions instead.

AlphaNum generates a pseudo-random alphanumeric string containing
length number of characters. It uses the characters A-Z, a-z, and
0-9.

Returns an error if n is negative.
*/
func AlphaNum(length int) (string, error) {
	return FromCharSet(length, setAlphaNum)
}

/*
Do not use for generating secure tokens! Use the Crypto*
functions instead.

Num generates a pseudo-random numeric string containing length
number of characters. It uses the characters 0-9.

Returns an error if n is negative.
*/
func Num(length int) (string, error) {
	return FromCharSet(length, setNum)
}

/*
Do not use for generating secure tokens! Use the Crypto*
functions instead.

Base64 generates a pseudo-random base 64 string containing
length number of characters. The character set used is A-Z,
a-z, 0-9, hyphen, and underscore. No padding characters are
used and it is URL-safe.

Returns an error if n is negative.
*/
func Base64(length int) (string, error) {
	return FromCharSet(length, setBase64)
}

/*
Do not use for generating secure tokens! Use the Crypto*
functions instead.

FromCharSet generates a pseudo-random string containing length
number of characters from the characters in charSet. Note that
length is measured in characters, not bytes.

Returns an error if length is negative or if charSet is an
empty string.

    // s will be something like "球界火陽地界妻水"
    s, _ := FromCharSet(8, "世界地球風火災水稲妻太陽")

*/
func FromCharSet(length int, charSet string) (string, error) {

	if length < 0 {
		return "", errors.New("length is negative.")
	}
	if charSet == "" {
		return "", errors.New("charSet is an empty string.")
	}

	set := strings.Split(charSet, "")
	if !uniqueSet(set) {
		return "", errors.New("duplicate characters in charSet.")
	}

	if len(set) < 2 {
		return "", errors.New("charSet is less than two characters.")
	}

	seedMu.Lock()
	seed++
	seedMu.Unlock()
	r := rand.New(rand.NewSource(seed))

	var s string
	for i := 0; i < length; i++ {
		s += set[r.Intn(len(set))]
	}

	return s, nil
}

func uniqueSet(ss []string) bool {
	seen := make(map[string]bool, len(ss))
	for _, s := range ss {
		if seen[s] {
			return false
		}
		seen[s] = true
	}
	return true
}
