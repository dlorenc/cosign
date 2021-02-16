/*
Copyright The Cosign Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package cli

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/peterbourgon/ff/v3/ffcli"
	"github.com/projectcosign/cosign/pkg/cosign"
)

func SignBlob() *ffcli.Command {
	var (
		flagset = flag.NewFlagSet("cosign sign-blob", flag.ExitOnError)
		key     = flagset.String("key", "", "path to the private key")
		b64     = flagset.Bool("b64", true, "whether to base64 encode the output")
	)
	return &ffcli.Command{
		Name:       "sign-blob",
		ShortUsage: "cosign sign-blob -key <key> [-sig <sig path>] <blob>",
		ShortHelp:  "Sign the supplied blob, outputting the base64-nocded signature to stdout",
		FlagSet:    flagset,
		Exec: func(ctx context.Context, args []string) error {
			if *key == "" {
				return flag.ErrHelp
			}

			if len(args) != 1 {
				return flag.ErrHelp
			}

			return SignBlobCmd(ctx, *key, args[0], *b64, getPass)
		},
	}
}

func SignBlobCmd(ctx context.Context, keyPath, payloadPath string, b64 bool, pf cosign.PassFunc) error {
	var payload []byte
	var err error
	if payloadPath == "-" {
		payload, err = ioutil.ReadAll(os.Stdin)
	} else {
		fmt.Fprintln(os.Stderr, "Using payload from:", payloadPath)
		payload, err = ioutil.ReadFile(payloadPath)
	}
	if err != nil {
		return err
	}

	pk, err := loadPk(keyPath, pf)

	signature := ed25519.Sign(pk, payload)
	fmt.Println(base64.StdEncoding.EncodeToString(signature))
	return nil
}

func loadPk(keyPath string, pf cosign.PassFunc) (ed25519.PrivateKey, error) {
	pass, err := pf(false)
	if err != nil {
		return nil, err
	}
	kb := []byte(os.Getenv("COSIGN_KEY"))
	if keyPath == "" && kb == nil {
		return nil, errors.New("Must specify -key or $COSIGN_KEY")
	}
	if keyPath != "" && kb != nil {
		return nil, errors.New("Must specify only one of -key or $COSIGN_KEY")
	}
	if keyPath != "" {
		kb, err = ioutil.ReadFile(keyPath)
		if err != nil {
			return nil, err
		}
	}

	pk, err := cosign.LoadPrivateKey(kb, pass)
	if err != nil {
		return nil, err
	}
	return pk, nil
}
