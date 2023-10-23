package bpp

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"

	"golang.org/x/crypto/argon2"
)

const (
	ErrSymbolsCount      = "number of symbols must be a multiple of four"
	ErrSymbolIsForbidden = "symbol is forbidden: %s"
	ErrBytesCount        = "number of bytes must be a multiple of three"
	ErrSaltLengthError   = "salt length error"
	ErrRandomizer        = "randomizer is broken"
)

const (
	FirstSymbol        = ' ' // White Space.
	LastSymbol         = '_' // Low Line.
	MinAllowedSymbol   = FirstSymbol
	MaxAllowedSymbol   = LastSymbol
	MinPasswordLength  = 16
	SaltLengthRequired = 1024
)

const (
	Argon2Iterations = 1
	Argon2Threads    = 4
	Argon2Memory     = 64 * 1024 // 64 MiB.
	Argon2KeyLength  = 1024
)

// PackSymbols packs each quad of symbols into three bytes.
func PackSymbols(symbols []rune) (ba []byte, err error) {
	symbolsCount := len(symbols)
	if symbolsCount%4 != 0 {
		return nil, errors.New(ErrSymbolsCount)
	}

	// Convert UTF-8 runes (of ASCII segment) into byte-sized numbers.
	var numbers = make([]byte, symbolsCount)
	for i, s := range symbols {
		numbers[i] = byte(s - FirstSymbol)
	}

	ba = make([]byte, 0, symbolsCount*3/4)

	// Process symbols by quads.
	// We pack each quad (4x6 = 24 bits) into 3 bytes (3x8 = 24 bits).
	var buf [3]byte
	var n byte
	iMax := len(numbers) - 1
	for i := 0; i <= iMax; {
		// N1.
		buf[0] = numbers[i] << 2

		// N2.
		n = numbers[i+1]
		buf[0] = buf[0] | (n >> 4)
		buf[1] = n << 4

		// N3.
		n = numbers[i+2]
		buf[1] = buf[1] | (n >> 2)
		buf[2] = n << 6

		// N4.
		buf[2] = buf[2] | numbers[i+3]

		// Next.
		ba = append(ba, buf[:]...)
		i = i + 4
	}

	return ba, nil
}

// UnpackBytes unpacks each triplet of bytes into four symbols.
func UnpackBytes(ba []byte) (symbols []rune, err error) {
	bytesCount := len(ba)
	if bytesCount%3 != 0 {
		return nil, errors.New(ErrBytesCount)
	}

	// Process bytes by triplets.
	// We unpack each triplet (3x8 = 24 bits) into 4 bytes (4x6 = 24 bits).
	var numbers = make([]byte, 0, bytesCount*4/3)
	var buf [4]byte
	iMax := len(ba) - 1
	for i := 0; i <= iMax; {
		// B1.
		buf[0] = ba[i] >> 2

		// B2.
		buf[1] = ((ba[i] << 6) >> 2) | (ba[i+1] >> 4)

		// B3.
		buf[2] = ((ba[i+1] << 4) >> 2) | (ba[i+2] >> 6)

		// B4.
		buf[3] = ba[i+2] & 63

		// Next.
		numbers = append(numbers, buf[:]...)
		i = i + 3
	}

	// Convert byte-sized numbers into UTF-8 runes (of ASCII segment).
	symbols = make([]rune, len(numbers))
	for i, n := range numbers {
		symbols[i] = rune(n + FirstSymbol)
	}

	return symbols, nil
}

// IsPasswordAllowed checks if the specified password is allowed.
func IsPasswordAllowed(pwd string) (ok bool, err error) {
	symbols := []rune(pwd)

	if (len(symbols)%4 != 0) || (len(symbols) < MinPasswordLength) {
		return false, errors.New(ErrSymbolsCount)
	}

	for _, s := range symbols {
		if (s < MinAllowedSymbol) || (s > MaxAllowedSymbol) {
			return false, fmt.Errorf(ErrSymbolIsForbidden, string(s))
		}
	}

	return true, nil
}

// MakeHashKey hashes the password and its salt.
func MakeHashKey(pwd string, salt []byte) (key []byte, err error) {
	var ok bool
	ok, err = IsPasswordAllowed(pwd)
	if !ok {
		return nil, err
	}

	if len(salt) != SaltLengthRequired {
		return nil, errors.New(ErrSaltLengthError)
	}

	var buf []byte
	buf, err = PackSymbols([]rune(pwd))
	if err != nil {
		return nil, err
	}

	key = argon2.IDKey(buf, salt, Argon2Iterations, Argon2Memory, Argon2Threads, Argon2KeyLength)

	return key, nil
}

// CheckHashKey hashes the password and salt and compares it with another key.
func CheckHashKey(pwd string, salt []byte, key []byte) (ok bool, err error) {
	var tmp []byte
	tmp, err = MakeHashKey(pwd, salt)
	if err != nil {
		return false, err
	}

	ok = bytes.Equal(key, tmp)

	return ok, nil
}

// GenerateRandomSalt creates a random salt which may be used for hashing.
func GenerateRandomSalt() (salt []byte, err error) {
	salt = make([]byte, SaltLengthRequired)

	var n int
	n, err = rand.Read(salt)
	if err != nil {
		return nil, err
	}
	if n != SaltLengthRequired {
		return nil, errors.New(ErrRandomizer)
	}

	return salt, nil
}
