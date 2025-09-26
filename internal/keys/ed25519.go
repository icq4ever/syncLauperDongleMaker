package keys

import(
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
)

/* =========================
   Ed25519 PEM helpers
   ========================= */

func LoadEd25519PrivFromPEM(path string) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	for {
		blk, rest := pem.Decode(b)
		if blk == nil {
			break
		}
		switch blk.Type {
		case "PRIVATE KEY": // PKCS#8
			k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
			if err != nil {
				return nil, err
			}
			if p, ok := k.(ed25519.PrivateKey); ok {
				return p, nil
			}
			return nil, errors.New("not Ed25519 private key")
		}
		b = rest
	}
	return nil, errors.New("no Ed25519 private key found in PEM")
}

func LoadEd25519PubFromPEM(path string) (ed25519.PublicKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	for {
		blk, rest := pem.Decode(b)
		if blk == nil {
			break
		}
		switch blk.Type {
		case "PUBLIC KEY": // PKIX
			pk, err := x509.ParsePKIXPublicKey(blk.Bytes)
			if err != nil {
				return nil, err
			}
			if p, ok := pk.(ed25519.PublicKey); ok {
				return p, nil
			}
			return nil, errors.New("not Ed25519 public key")
		}
		b = rest
	}
	return nil, errors.New("no Ed25519 public key found in PEM")
}
