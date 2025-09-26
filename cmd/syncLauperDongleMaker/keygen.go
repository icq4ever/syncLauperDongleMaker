package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
)

/* =========================
   keygen (Ed25519 전용)
   ========================= */
func cmdKeygen() {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	outPriv := fs.String("out-priv", "privkey.pem", "Ed25519 private key PEM (PKCS#8)")
	outPub := fs.String("out-pub", "pubkey.pem", "Ed25519 public key PEM (PKIX)")
	_ = fs.Parse(os.Args[2:])

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	must(err)

	// PRIVATE KEY (PKCS#8)
	privDer, err := x509.MarshalPKCS8PrivateKey(priv)
	must(err)
	privBlk := &pem.Block{Type: "PRIVATE KEY", Bytes: privDer}
	must(os.WriteFile(*outPriv, pem.EncodeToMemory(privBlk), 0600))

	// PUBLIC KEY (PKIX)
	pubDer, err := x509.MarshalPKIXPublicKey(pub)
	must(err)
	pubBlk := &pem.Block{Type: "PUBLIC KEY", Bytes: pubDer}
	must(os.WriteFile(*outPub, pem.EncodeToMemory(pubBlk), 0644))

	fmt.Printf("keygen: wrote %s and %s (Ed25519)\n", *outPriv, *outPub)
}

