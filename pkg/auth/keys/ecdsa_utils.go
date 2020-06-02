package keys

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"net/http"
)

// PemEncodePublicKey transforms a *ecdsa.PublicKey into a pem encoded string
func PemEncodePublicKey(pubKey *ecdsa.PublicKey) (string, error) {
	encoded, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: encoded})), nil
}

// PemDecodePublicKey transforms a pem encoded string into a *ecdsa.PublicKey
func PemDecodePublicKey(pubKey string) (*ecdsa.PublicKey, error) {
	decoded, _ := pem.Decode([]byte(pubKey))
	keyBytes := decoded.Bytes
	publicKey, err := x509.ParsePKIXPublicKey(keyBytes)
	if err != nil {
		return nil, err
	}
	return publicKey.(*ecdsa.PublicKey), nil
}

// PemEncodePrivateKey transforms a *ecdsa.PrivateKey into a pem encoded string
func PemEncodePrivateKey(pvKey *ecdsa.PrivateKey) (string, error) {
	encoded, err := x509.MarshalECPrivateKey(pvKey)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded})), nil
}

// PemDecodePrivateKey transforms a pem encoded string into a *ecdsa.PrivateKey
func PemDecodePrivateKey(pvKey string) (*ecdsa.PrivateKey, error) {
	decoded, _ := pem.Decode([]byte(pvKey))
	keyBytes := decoded.Bytes
	return x509.ParseECPrivateKey(keyBytes)
}

// ReadPrivateKeyFromFile reads a file containing a pem encoded key into a *ecdsa.PrivateKey
func ReadPrivateKeyFromFile(path string) (*ecdsa.PrivateKey, error) {
	content, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return PemDecodePrivateKey(string(content))
}

// ReadPublicKeyFromFile reads a file containing a pem encoded key into a *ecdsa.PublicKey
func ReadPublicKeyFromFile(path string) (*ecdsa.PublicKey, error) {
	content, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return PemDecodePublicKey(string(content))
}

// ReadRemotePublicKey reads a pem encoded key from an url into a *ecdsa.PublicKey
func ReadRemotePublicKey(url string) (*ecdsa.PublicKey, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	key, err := ioutil.ReadAll(resp.Body)

	return PemDecodePublicKey(string(key))
}
