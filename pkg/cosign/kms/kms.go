/*
Copyright The Sigstore Authors

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

package kms

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"strings"

	"github.com/google/go-containerregistry/pkg/v1/remote"
)

type KMS interface {
	// CreateKey is responsible for creating an asymmetric key pair
	// with the ECDSA algorithm on the P-256 Curve with a SHA-256 digest
	CreateKey(context.Context) error

	// Sign is responsible for signing an image via the keys
	// stored in KMS
	Sign(ctx context.Context, img *remote.Descriptor, payload []byte) (signature []byte, err error)

	// PublicKey returns the public key stored in the KMS
	PublicKey(ctx context.Context) (*ecdsa.PublicKey, error)
}

// schemes for various KMS services are copied from https://github.com/google/go-cloud/tree/master/secrets
const gcpScheme = "gcpkms://"

func Get(ctx context.Context, keyResourceID string) (KMS, error) {
	id := strings.SplitAfter(keyResourceID, "://")
	if len(id) != 2 {
		return nil, errors.New("please format the kms key as gcpkms://projects/[PROJECT_ID]/locations/[LOCATION]/keyRings/[KEY_RING]/cryptoKeys/[KEY]")
	}
	switch scheme := id[0]; scheme {
	case gcpScheme:
		return newGCP(ctx, id[1])
	default:
		return nil, errors.New("currently only GCP KMS is supported")
	}
}
