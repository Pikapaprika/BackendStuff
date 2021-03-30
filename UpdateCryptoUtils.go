package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
)

type RSASigner struct {
	privateKey *rsa.PrivateKey
}

func NewRSASigner(privateKeyPath string) (*RSASigner, error) {
	key, err := loadRSAPrivateKey(privateKeyPath)
	if err != nil {
		return nil, err
	}
	signer := RSASigner{key}
	return &signer, nil
}

func (signer RSASigner) signHash(data []byte, hashFunc crypto.Hash) ([]byte, error) {
	return rsa.SignPKCS1v15(rand.Reader, signer.privateKey, hashFunc, data)
}
func (signer RSASigner) signSHA256Digest(data [32]byte) (*[32]byte, error) {
	sig, err := rsa.SignPKCS1v15(rand.Reader, signer.privateKey, crypto.SHA256, data[:])
	if err!= nil {
		return nil, err
	}
	var cpy [32]byte
	copy(cpy[:], sig)
	return &cpy, nil
}

func loadRSAPrivateKey(path string) (*rsa.PrivateKey, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseRSAPrivateKey(data)
}

// Based on: https://gist.github.com/raztud/0e9b3d15a32ec6a5840e446c8e81e308
func parseRSAPrivateKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("Private Key could not be parsed (no key found).")
	}

	var privKey *rsa.PrivateKey
	switch block.Type {
	case "RSA PRIVATE KEY":
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		privKey = key

	default:
		return nil, fmt.Errorf("private Key could not be parsed (unsupported type %q", block.Type)
	}
	return privKey, nil
}

