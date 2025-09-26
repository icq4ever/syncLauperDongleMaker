package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"os"

	"syncLauperDongleMaker/internal/config"
)

/* =========================
   keygen (Ed25519 전용)
   ========================= */
func cmdKeygen() {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	kind := fs.String("kind", "prov", "which pair to generate: prov/issuer")
	outPriv := fs.String("out-priv", config.ProvPrivDefault, "Ed25519 private key PEM (PKCS#8)")
	outPub := fs.String("out-pub", config.ProvPubDefault, "Ed25519 public key PEM (PKIX)")

	_ = fs.Parse(os.Args[2:])

	// 어떤 플래그가 실제로 전달되었는지 기록
	seen := map[string]bool{}
	fs.Visit(func(f *flag.Flag) {seen[f.Name] = true})

	if *kind == "issuer" {
		if !seen["out-priv"] { *outPriv = config.IssuerPrivDefault }
		if !seen["out-pub"]  { *outPub  = config.IssuerPubDefault  }
	}

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

