package main

import (
	"bufio"
	"encoding/base64"
	"flag"
	"os"

	"github.com/vault-thirteen/auxie/cio"
	"github.com/vault-thirteen/auxie/errors"

	"github.com/vault-thirteen/BytePackedPassword"
)

const (
	Err_PasswordIsNotSet = "password is not set"
	Err_SaltIsNotSet     = "salt is not set"
)

const (
	ExitCode_Error = 1
)

const (
	Msg_EnterSaltBytesB64 = "Enter salt bytes encoded as Base64URL:"

	Msgf_Key = "Key: %v."
)

func main() {
	pwd, salt, err := receiveArguments()
	mustBeNoError(err)

	var hash []byte
	hash, err = bpp.MakeHashKey(pwd, salt)
	mustBeNoError(err)

	hashB64U := base64.StdEncoding.EncodeToString(hash)

	cio.PrintMessage(cio.FormatMessage(Msgf_Key, hashB64U))
}

func mustBeNoError(err error) {
	if err != nil {
		cio.LogMessage(err)
		os.Exit(ExitCode_Error)
	}
}

func receiveArguments() (pwd string, salt []byte, err error) {
	flag.StringVar(&pwd, "p", "", "password string")
	var saltStr string
	flag.StringVar(&saltStr, "s", "", "salt bytes encoded as Base64URL")
	flag.Parse()

	if len(pwd) == 0 {
		return "", nil, errors.ErrorFromText(Err_PasswordIsNotSet)
	}

	if saltStr == "?" {
		cio.PrintMessage(Msg_EnterSaltBytesB64)

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
		return "", nil, errors.ErrorFromText(Err_SaltIsNotSet)
	}

	return pwd, salt, nil
}
