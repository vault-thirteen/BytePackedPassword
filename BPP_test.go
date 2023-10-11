package bpp

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/vault-thirteen/tester"
)

func Test_PackAndUnpack(t *testing.T) {
	aTest := tester.New(t)

	var ba []byte
	var symbols []rune
	var err error

	// Test negative cases.
	fmt.Println("Part 1/4")
	ba, err = PackSymbols([]rune(`!x`))
	aTest.MustBeAnError(err)
	aTest.MustBeEqual(ba, []uint8(nil))
	//
	symbols, err = UnpackBytes([]byte{1})
	aTest.MustBeAnError(err)
	aTest.MustBeEqual(symbols, []rune(nil))

	// Test positive cases.
	fmt.Println("Part 2/4")
	ba, err = PackSymbols([]rune(`!"AB`))
	aTest.MustBeNoError(err)
	aTest.MustBeEqual(ba, []uint8{4, 40, 98})
	//
	symbols, err = UnpackBytes([]byte{4, 40, 98})
	aTest.MustBeNoError(err)
	aTest.MustBeEqual(symbols, []rune{'!', '"', 'A', 'B'})

	// Test all the combinations.
	// Packing and unpacking.
	fmt.Println("Part 3/4")
	var asciiSymbols = []rune{
		'0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
		'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
		'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
		' ', '!', '"', '#', '$', '%', '&', '\'', '(', ')', '*', '+', ',', '-',
		'.', '/', ':', ';', '<', '=', '>', '?', '@', '[', '\\', ']', '^', '_',
	}
	for _, s1 := range asciiSymbols {
		for _, s2 := range asciiSymbols {
			for _, s3 := range asciiSymbols {
				for _, s4 := range asciiSymbols {
					ba, err = PackSymbols([]rune{s1, s2, s3, s4})
					aTest.MustBeNoError(err)
					symbols, err = UnpackBytes(ba)
					aTest.MustBeNoError(err)
					aTest.MustBeEqual(symbols, []rune{s1, s2, s3, s4})
				}
			}
		}
	}

	// Test all the combinations.
	// Unpacking and packing.
	fmt.Println("Part 4/4")
	for b1 := 0; b1 <= 255; b1++ {
		for b2 := 0; b2 <= 255; b2++ {
			for b3 := 0; b3 <= 255; b3++ {
				tmp := []byte{byte(b1), byte(b2), byte(b3)}
				symbols, err = UnpackBytes(tmp)
				aTest.MustBeNoError(err)
				ba, err = PackSymbols(symbols)
				aTest.MustBeNoError(err)
				aTest.MustBeEqual(ba, tmp)
			}
		}
	}
}

func Test_SelfCheck(t *testing.T) {
	aTest := tester.New(t)
	aTest.MustBeEqual(FirstSymbol, int32(0x20))
	aTest.MustBeEqual(LastSymbol, int32(0x5F))
}

func Test_IsPasswordAllowed(t *testing.T) {
	aTest := tester.New(t)

	var ok bool
	var err error

	// Test #1. Length is not a multiple of four.
	ok, err = IsPasswordAllowed("1234567890123")
	aTest.MustBeAnError(err)
	aTest.MustBeEqual(ok, false)

	// Test #2. Length is too small
	ok, err = IsPasswordAllowed("1234")
	aTest.MustBeAnError(err)
	aTest.MustBeEqual(ok, false)

	// Test #3. Symbol is out of range.
	ok, err = IsPasswordAllowed("123456789012345`")
	aTest.MustBeAnError(err)
	aTest.MustBeEqual(ok, false)

	// Test #4. Symbol is out of range.
	ok, err = IsPasswordAllowed("123456789012345" + string(rune(0x1F)))
	aTest.MustBeAnError(err)
	aTest.MustBeEqual(ok, false)

	// Test #5. Positive case.
	ok, err = IsPasswordAllowed("1234567890123456")
	aTest.MustBeNoError(err)
	aTest.MustBeEqual(ok, true)
}

func Test_MakeHashKey(t *testing.T) {
	aTest := tester.New(t)

	var salt []byte
	var key []byte
	var err error

	// Test #1. Password is bad.
	key, err = MakeHashKey("123", []byte{})
	aTest.MustBeAnError(err)
	aTest.MustBeEqual(key, []byte(nil))

	// Test #2. Salt is bad.
	key, err = MakeHashKey("1234567890123456", []byte{})
	aTest.MustBeAnError(err)
	aTest.MustBeEqual(key, []byte(nil))

	// Test #3. Salt is good.
	salt = make([]byte, 0, 1024)
	for i := 1; i <= 1024; i++ {
		salt = append(salt, byte(i))
	}
	key, err = MakeHashKey("1234567890123456", salt)
	aTest.MustBeNoError(err)
	aTest.MustBeEqual(len(key), Argon2KeyLength)

	fmt.Println("Please wait ...")

	// Test #4. Constant results.
	for i := 1; i <= 1024; i++ {
		keyPrev := key
		key, err = MakeHashKey("1234567890123456", salt)
		aTest.MustBeNoError(err)
		aTest.MustBeEqual(len(key), Argon2KeyLength)
		aTest.MustBeEqual(key, keyPrev)
	}

	// Test #5. Password with old salt.
	keyPrev := key
	key, err = MakeHashKey("123456789012345X", salt)
	aTest.MustBeNoError(err)
	aTest.MustBeEqual(len(key), Argon2KeyLength)
	aTest.MustBeDifferent(key, keyPrev)

	// Test #6. Same password with different salts.
	pwd := "1234567890123456"

	salt1 := make([]byte, 0, 1024)
	for i := 1; i <= 1024; i++ {
		salt1 = append(salt1, byte(i))
	}

	salt2 := make([]byte, 0, 1024)
	for i := 1; i <= 1024; i++ {
		salt2 = append(salt2, byte(i))
	}
	salt2[0] = salt1[0] + 1

	var key1, key2 []byte
	key1, err = MakeHashKey(pwd, salt1)
	aTest.MustBeNoError(err)
	key2, err = MakeHashKey(pwd, salt2)
	aTest.MustBeNoError(err)
	aTest.MustBeDifferent(key1, key2)
}

func Test_CheckHashKey(t *testing.T) {
	aTest := tester.New(t)

	var key []byte
	var err error

	pwd := "1234567890123456"

	salt := make([]byte, 0, 1024)
	for i := 1; i <= 1024; i++ {
		salt = append(salt, byte(i))
	}

	checkedKey := []byte{
		178, 76, 236, 168, 199, 129, 68, 226, 148, 57, 132, 156, 212, 32, 232,
		131, 179, 93, 48, 38, 150, 180, 168, 208, 75, 18, 170, 195, 27, 231,
		141, 154, 217, 173, 159, 70, 157, 79, 21, 203, 70, 54, 20, 123, 154,
		204, 69, 237, 237, 154, 171, 83, 72, 40, 160, 91, 185, 125, 181, 119,
		125, 109, 35, 54, 57, 30, 177, 160, 22, 238, 198, 206, 154, 17, 126,
		228, 109, 44, 159, 242, 204, 102, 37, 122, 17, 53, 214, 55, 116, 20,
		160, 84, 4, 78, 179, 47, 251, 55, 206, 243, 64, 134, 43, 242, 176, 245,
		198, 152, 22, 44, 123, 93, 229, 29, 26, 251, 211, 5, 222, 107, 144,
		156, 105, 229, 113, 151, 198, 161, 23, 183, 207, 253, 151, 60, 203,
		231, 182, 107, 172, 58, 159, 175, 217, 102, 120, 102, 93, 242, 230, 55,
		30, 43, 39, 189, 35, 226, 225, 113, 186, 112, 226, 147, 94, 214, 182,
		228, 68, 61, 137, 175, 226, 3, 184, 187, 250, 121, 97, 195, 123, 38,
		106, 234, 93, 191, 193, 54, 152, 47, 248, 215, 91, 178, 225, 58, 66,
		114, 101, 4, 78, 40, 32, 210, 91, 243, 118, 106, 63, 240, 221, 224,
		160, 101, 61, 37, 180, 25, 207, 87, 2, 35, 73, 184, 204, 204, 230, 153,
		81, 123, 194, 45, 251, 149, 122, 97, 105, 63, 153, 72, 185, 100, 242,
		151, 104, 106, 32, 109, 138, 22, 134, 124, 132, 233, 218, 44, 31, 18,
		94, 58, 7, 54, 212, 138, 166, 98, 218, 157, 48, 171, 35, 118, 37, 195,
		45, 15, 221, 28, 100, 84, 92, 31, 69, 195, 155, 164, 175, 173, 162,
		244, 143, 174, 25, 222, 161, 102, 61, 107, 163, 193, 32, 80, 158, 106,
		115, 118, 252, 228, 178, 98, 113, 35, 245, 199, 124, 16, 12, 3, 235,
		163, 38, 136, 240, 178, 188, 4, 121, 156, 240, 37, 75, 211, 171, 68,
		139, 199, 101, 77, 97, 0, 112, 195, 6, 141, 207, 231, 232, 38, 82, 88,
		235, 223, 46, 247, 194, 76, 183, 130, 118, 115, 181, 7, 99, 1, 171,
		140, 240, 32, 65, 127, 200, 59, 49, 197, 159, 28, 215, 1, 21, 64, 52,
		162, 105, 36, 22, 107, 216, 51, 133, 142, 31, 124, 117, 5, 180, 211,
		174, 210, 122, 253, 215, 100, 47, 84, 164, 86, 166, 152, 14, 168, 209,
		100, 53, 1, 166, 127, 164, 66, 122, 63, 33, 63, 186, 20, 153, 134, 89,
		183, 183, 231, 169, 121, 142, 170, 64, 236, 26, 198, 254, 117, 183,
		184, 216, 63, 130, 144, 129, 229, 80, 189, 82, 58, 190, 36, 199, 121,
		215, 111, 193, 21, 152, 246, 162, 88, 37, 61, 238, 116, 177, 142, 55,
		6, 192, 183, 243, 160, 201, 159, 89, 133, 16, 216, 195, 147, 227, 21,
		177, 181, 192, 75, 213, 250, 150, 53, 136, 140, 171, 229, 24, 29, 196,
		73, 21, 14, 56, 88, 17, 169, 5, 168, 71, 95, 71, 85, 105, 157, 179, 70,
		173, 131, 168, 165, 76, 168, 93, 79, 4, 212, 41, 205, 174, 120, 197,
		127, 37, 56, 87, 13, 249, 30, 251, 134, 33, 47, 249, 2, 254, 177, 53,
		8, 120, 49, 29, 53, 114, 52, 150, 39, 156, 205, 7, 255, 18, 44, 142,
		239, 105, 193, 48, 101, 5, 143, 118, 220, 53, 52, 93, 93, 182, 98, 101,
		102, 203, 213, 248, 123, 180, 228, 221, 174, 136, 17, 117, 98, 76, 243,
		244, 81, 111, 114, 47, 31, 90, 212, 20, 140, 177, 104, 141, 85, 32,
		164, 84, 12, 208, 226, 210, 151, 169, 142, 242, 125, 21, 229, 222, 187,
		241, 65, 188, 21, 217, 128, 57, 91, 246, 41, 40, 38, 69, 4, 233, 113,
		215, 144, 71, 88, 215, 220, 46, 61, 82, 136, 36, 132, 30, 66, 84, 17,
		199, 43, 119, 243, 4, 110, 34, 146, 8, 103, 60, 149, 89, 192, 150, 40,
		94, 175, 185, 73, 70, 110, 162, 80, 149, 51, 196, 112, 158, 101, 223,
		91, 69, 86, 52, 240, 59, 10, 114, 13, 99, 28, 231, 67, 125, 35, 211,
		146, 155, 252, 159, 125, 23, 52, 250, 127, 126, 139, 108, 132, 20, 232,
		168, 195, 191, 179, 28, 205, 240, 77, 83, 1, 75, 39, 128, 146, 62, 62,
		216, 30, 138, 125, 109, 91, 188, 88, 57, 142, 231, 224, 84, 226, 171,
		61, 141, 255, 35, 141, 62, 78, 224, 11, 23, 110, 14, 210, 248, 62, 170,
		232, 141, 221, 79, 184, 236, 125, 155, 203, 70, 149, 149, 27, 126, 139,
		195, 42, 41, 213, 201, 208, 164, 118, 26, 7, 255, 15, 194, 223, 235,
		236, 234, 196, 212, 221, 169, 128, 9, 37, 152, 114, 90, 197, 96, 150,
		21, 44, 238, 239, 157, 85, 16, 227, 138, 169, 0, 112, 104, 52, 250, 31,
		117, 186, 34, 245, 125, 137, 81, 232, 198, 69, 58, 18, 73, 10, 149,
		224, 205, 21, 237, 236, 60, 98, 240, 106, 185, 6, 231, 35, 210, 46,
		129, 85, 163, 224, 71, 22, 58, 139, 206, 218, 177, 232, 220, 7, 241,
		192, 151, 32, 171, 72, 159, 67, 57, 185, 150, 103, 193, 54, 77, 207,
		97, 230, 103, 21, 217, 166, 181, 199, 58, 248, 111, 113, 210, 69, 26,
		63, 119, 222, 53, 30, 27, 85, 113, 130, 56, 113, 234, 217, 54, 252, 90,
		7, 21, 85, 244, 43, 2, 41, 98, 31, 78, 46, 146, 237, 52, 115, 217, 22,
		78, 71, 77, 131, 27, 60, 49, 201, 240, 37, 40, 87, 114, 254, 171, 35,
		116, 202, 89, 131, 50, 133, 242, 81, 191, 203, 64, 172, 141, 145, 233,
		237, 19, 212, 115, 33, 173, 245, 37, 142, 176, 204, 146, 97, 81, 175,
		46, 153, 127, 45, 34, 113, 176, 162, 92, 4, 22, 65, 226, 136, 26, 62,
		56, 157, 48, 225, 172, 209, 248, 64, 85, 201, 85, 87, 13, 232, 115,
		105, 96, 254, 233, 236, 159, 215, 109, 127, 170, 251, 185, 10}

	key, err = MakeHashKey(pwd, salt)
	aTest.MustBeNoError(err)
	aTest.MustBeEqual(key, checkedKey) // This can not fail.
	// It is fails, then the algorithm has changed over time !

	var ok bool
	ok, err = CheckHashKey(pwd, salt, checkedKey)
	aTest.MustBeNoError(err)
	aTest.MustBeEqual(ok, true)
}

func Test_GenerateRandomSalt(t *testing.T) {
	aTest := tester.New(t)

	var salt []byte
	var err error

	var n = 50_000
	salts := make([][]byte, 0, n)
	fmt.Println("Please wait ...")

	for i := 1; i <= n; i++ {
		salt, err = GenerateRandomSalt()
		aTest.MustBeNoError(err)
		aTest.MustBeEqual(len(salt), SaltLengthRequired)

		// Salt must be unique.
		for _, s := range salts {
			if bytes.Equal(s, salt) {
				t.Fail()
			}
		}

		salts = append(salts, salt)
	}
}
