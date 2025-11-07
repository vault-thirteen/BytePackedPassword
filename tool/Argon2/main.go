package main

import (
	"bufio"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/vault-thirteen/BytePackedPassword"
)

const (
	ErrPasswordIsNotSet = "password is not set"
	ErrSaltIsNotSet     = "salt is not set"
)

func main() {
	pwd, salt, err := receiveArguments()
	mustBeNoError(err)

	var hash []byte
	hash, err = bpp.MakeHashKey(pwd, salt)
	mustBeNoError(err)

	hashB64U := base64.StdEncoding.EncodeToString(hash)

	//fmt.Println(fmt.Sprint("pwd: %v, salt: %v.", pwd, salt))
	fmt.Println(fmt.Sprintf("Key: %v.", hashB64U))
}

func mustBeNoError(err error) {
	if err != nil {
		log.Fatalln(err.Error())
	}
}

func receiveArguments() (pwd string, salt []byte, err error) {
	flag.StringVar(&pwd, "p", "", "password string")
	var saltStr string
	flag.StringVar(&saltStr, "s", "", "salt bytes encoded as Base64URL")
	flag.Parse()

	if len(pwd) == 0 {
		return "", nil, errors.New(ErrPasswordIsNotSet)
	}

	if saltStr == "?" {
		fmt.Println("Enter salt bytes encoded as Base64URL:")

		//_, err = fmt.Scanln(&saltStr) // <- This shit is still bugged with 255 symbols limit.
		scanner := bufio.NewScanner(os.Stdin)
		scanner.Scan()
		err = scanner.Err()
		if err != nil {
			return "", nil, err
		}
		saltStr = scanner.Text()
	}

	salt, err = base64.StdEncoding.DecodeString(saltStr)
	if err != nil {
		return "", nil, err
	}

	if len(salt) == 0 {
		return "", nil, errors.New(ErrSaltIsNotSet)
	}

	return pwd, salt, nil
}
