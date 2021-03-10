/*
Copyright The Rekor Authors

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

package cosign

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

type SignedPayload struct {
	Base64Signature string
	Payload         []byte
	Cert            *x509.Certificate
	Chain           []*x509.Certificate
}

func Munge(desc v1.Descriptor) string {
	// sha256:... -> sha256-...
	munged := strings.ReplaceAll(desc.Digest.String(), ":", "-")
	munged += ".cosign"
	return munged
}

func FetchSignatures(ref name.Reference) ([]SignedPayload, *v1.Descriptor, error) {
	var sigRef name.Reference
	targetDesc, err := remote.Get(ref, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		return nil, nil, err
	}
	sigRef = ref.Context().Tag(Munge(targetDesc.Descriptor))

	sigImg, err := remote.Image(sigRef, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		return nil, nil, err
	}

	m, err := sigImg.Manifest()
	if err != nil {
		return nil, nil, err
	}

	signatures := []SignedPayload{}
	for _, desc := range m.Layers {
		base64sig, ok := desc.Annotations[sigkey]
		if !ok {
			continue
		}
		l, err := sigImg.LayerByDigest(desc.Digest)
		if err != nil {
			return nil, nil, err
		}

		// Compressed is a misnomer here, we just want the raw bytes from the registry.
		r, err := l.Compressed()
		if err != nil {
			return nil, nil, err

		}
		payload, err := ioutil.ReadAll(r)
		if err != nil {
			return nil, nil, err
		}

		sp := SignedPayload{
			Payload:         payload,
			Base64Signature: base64sig,
		}

		// We may have a certificate and chain
		certPem := desc.Annotations[certkey]
		if certPem != "" {
			certs, err := LoadCerts(certPem)
			if err != nil {
				return nil, nil, err
			}
			if len(certs) != 1 {
				return nil, nil, fmt.Errorf("expected 1 certificate, found %d", len(certs))
			}
			sp.Cert = certs[0]
		}
		chainPem := desc.Annotations[chainkey]
		if chainPem != "" {
			certs, err := LoadCerts(chainPem)
			if err != nil {
				return nil, nil, err
			}
			sp.Chain = certs
		}

		signatures = append(signatures, sp)
	}
	return signatures, &targetDesc.Descriptor, nil
}

func LoadCerts(pemStr string) ([]*x509.Certificate, error) {
	blocks := []*pem.Block{}
	pemBytes := []byte(pemStr)
	for {
		block, rest := pem.Decode(pemBytes)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			blocks = append(blocks, block)
		}
		pemBytes = rest
	}

	certs := []*x509.Certificate{}
	for _, block := range blocks {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}
	return certs, nil
}
