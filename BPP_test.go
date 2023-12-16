package bpp

import (
	"bytes"
	"encoding/base64"
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

	// Test #7. Random salt + Simple password.
	pwd = "PASSWORDPASSWORD"
	fmt.Println("Password (unpacked): ", pwd)
	salt, err = GenerateRandomSalt()
	aTest.MustBeNoError(err)
	fmt.Println("Salt: ", base64.StdEncoding.EncodeToString(salt))
	key, err = MakeHashKey(pwd, salt)
	aTest.MustBeNoError(err)
	fmt.Println("Key: ", base64.StdEncoding.EncodeToString(key))
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
	fmt.Println("Salt: ", base64.StdEncoding.EncodeToString(salt))

	checkedKeyBase64 := "+8FAH+c5OGWX2wQUhU1dh0ylhPA5Y4buCdQ0AnyH1gKWMMdowV/f7sBuyR4TzlT+Reqfi3RLGLi4wmTybOQ0LXIqDIIWSvHWCing+y35+DRs9YZeVeRxrjuPN5zTj6iBisb4pPUiaGPNeyw3+RjPGoshg8TB7AfjlO8qVECsW6GaUHFSgS6E4I3ft4+8LM28oLKe0wQfz4nzcf59rND2/ACiyZ842YEjQi/qR0QxLlOJbJztR+ILSUQ99gPeD0ZklQuiY/Aw3rwZWKDVTERUinhLiBbDLj0X3ngR4ibnFmure+VWxuiUK3/TbUL2eBy+v/n00tnxpyJdUdHhbbSbEqAZMMhn5i0S/nnDWmTdyZc6JIRFD3pnzDWBOGS/kX6KIU40b3H2nVxEY+VmKoVLpfR/OT4ErgULEsBIJzqusZFOoAJYo3mbixukj0rk1tMy+d4Cj4KnC5zZS/DBQvzPgQOkQJT63++4l6PSTt11AK2RxbsrvVvkCZIiP+mrTchxOYqiDVSPTA0jWMyix9TNe/wCvgk26eyXMpFNrCZRTHqRpXnYnxh9twXqrov7lJ96Nxt7vmSA6lU4pGahACygByu1IPqCkrcehAK4zjo+zeT0iTkR0D1VxkUCoz8Fbbj2HOM/mOL/ZXmjnzt6yXGo2cmWOX99/J2lD7SIawgWRIJAIgMgEinbp4yyNddLasrSb3dFWakEMqQvnolw41TMTHcK/ZtJl4qoWKHIq4W5Z0iVo8flAcRmilL26FlAQsqTO6nHiDkFANBXcsnRm+XPB+6fLtfLcWaX9EoHaRY03KoOmAwLnpns3HF0jeELuD+f/1B5oOmnXQ0x1Ia0M+3/TLcSMROgqnOY5O6lBivbAh7EDOxMvwcK84i8l0ImOzXoCnf98rxTh8HmNhbQpjPrCSE2cFjt3e0EZJcICXuQFjMM/v7pGI2lno3dbxWqRxjBmSjz5uv6sd820idZ53/pXj9Jv4z/L3UfGownx+uc0be00VWz9vjaVMGYYKdYhXgH8BIsHvF+6BMnLp2tPBSx8q3XknsA1e0QicNFRNvXNbz5VwsKtxZhRNm+MWF1d6wcrc1u8LUKpdrQc9tI0u77r3sgkrvmSzORGc8u5F5dmdLCTxxrR+FmAal0j8VEfqPlh0cQfoEYyDZ5bshLhMs+X1wVV2zkKv1D6gtjzxSjTL0aGYLokft38p4Iaj0ff4WPp3VPzFeihokGQr4lxfIFtuDwX8Pw34JNIIb152XJZIPgR+ze3OrbMESK+6OY3KqHPJLIUZs3J29ADN6zn2JPV8upfAjB1AtR2qYXcBEf33UpAUDlzBOGyYfT9fzt+GKT+NOQRAo1PQxO6oxKy2wGrQ=="
	fmt.Println("Key (expected): ", checkedKeyBase64)

	var checkedKey []byte
	checkedKey, err = base64.StdEncoding.DecodeString(checkedKeyBase64)
	aTest.MustBeNoError(err)

	key, err = MakeHashKey(pwd, salt)
	aTest.MustBeNoError(err)
	aTest.MustBeEqual(key, checkedKey)

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
