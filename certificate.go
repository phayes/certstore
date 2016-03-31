package main

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"strings"
)

var (
	ErrDSANotSupported       = errors.New("DSA Is not supported. Please use RSA or ECDSA.")
	ErrInvalidPEMBlock       = errors.New("Invalid PEM Block. Please only include a single PEM Block per field.")
	ErrInvalidCertificatePEM = errors.New("Invalid Certificate")
	ErrInvalidCertificateId  = errors.New("Invaid Certificate ID. The Certificate ID is the SHA256 hash (hex-encoded) of the Certificate data (DER-encoded)")
	ErrInvalidPrivateKey     = errors.New("Invalid Private Key. The provided key does not match the certificate.")
	ErrMissingPrivateKey     = errors.New("No Private Key provided.")
	ErrKeyTooSmall           = errors.New("The key is of insufficient length to provide good security. A minimum key size of 1024 for RSA or 168 for EC must be used.")
)

type Certificate struct {
	Id     string // SHA256 hash (hex-encoded) of the certificate data (DER-encoded)
	UserId string
	Active bool
	Cert   *x509.Certificate
	Key    interface{} // Could be RSA or DSA Private Key
}

// CertificateData is an intermediary representation of a Certificate
// This intermediary form does not parse the ASN1 strings, nor does it verify any of the data
// It is used for two things:
// 1. Easy JSON marshalling / unmarshalling
// 2. Retreival from the database and delivery to the client (no parsing overhead)
type CertificateData struct {
	Id     string `json:"id"`
	UserId string `json:"user"`
	Active bool   `json:"active"`
	Cert   string `json:"cert"`
	Key    string `json:"key"`
}

func NewCertificateFromData(certData *CertificateData) (*Certificate, error) {
	cert := &Certificate{
		Id:     certData.Id,
		UserId: certData.UserId,
		Active: certData.Active,
	}

	// Parse the certificate
	certPEMBlockBytes, err := PEMBlockNormalize(certData.Cert)
	if err != nil {
		return nil, err
	}
	certPEMBlock, _ := pem.Decode(certPEMBlockBytes)
	if certPEMBlock == nil {
		return nil, ErrInvalidCertificatePEM
	}
	if certPEMBlock.Type != "CERTIFICATE" {
		return nil, ErrInvalidCertificatePEM
	}
	cert.Cert, err = x509.ParseCertificate(certPEMBlock.Bytes)
	if err != nil {
		return nil, err
	}

	// Parse the private key
	keyPEMBlockBytes, err := PEMBlockNormalize(certData.Key)
	if err != nil {
		return nil, err
	}
	keyPEMBlock, _ := pem.Decode(keyPEMBlockBytes)
	if keyPEMBlock == nil {
		return nil, ErrMissingPrivateKey
	}
	if keyPEMBlock.Type == "DSA PRIVATE KEY" {
		return nil, ErrDSANotSupported
	}
	if keyPEMBlock.Type != "RSA PRIVATE KEY" && keyPEMBlock.Type != "EC PRIVATE KEY" && keyPEMBlock.Type != "PRIVATE KEY" {
		return nil, ErrMissingPrivateKey
	}
	if keyPEMBlock.Type == "RSA PRIVATE KEY" {
		cert.Key, err = x509.ParsePKCS1PrivateKey(keyPEMBlock.Bytes)
		if err != nil {
			return nil, err
		}
	}
	if keyPEMBlock.Type == "EC PRIVATE KEY" {
		cert.Key, err = x509.ParseECPrivateKey(keyPEMBlock.Bytes)
		if err != nil {
			return nil, err
		}
	}
	if keyPEMBlock.Type == "PRIVATE KEY" {
		cert.Key, err = x509.ParsePKCS8PrivateKey(keyPEMBlock.Bytes)
		if err != nil {
			return nil, err
		}
	}

	// If the Id is empty, generate it
	if certData.Id == "" {
		hash := sha256.Sum256(certPEMBlock.Bytes)
		cert.Id = hex.EncodeToString(hash[:])
	}

	// Verify the certificate
	err = cert.Verify()
	if err != nil {
		return nil, err
	}

	// All is well
	return cert, nil
}

func (cert *Certificate) Verify() error {
	// Verify the entire certificate chain
	if OptVerifyCertificate {
		_, err := cert.Cert.Verify(x509.VerifyOptions{})
		if err != nil {
			return err
		}
	}

	// Verify the ID
	hash := sha256.Sum256(cert.Cert.Raw)
	if cert.Id != hex.EncodeToString(hash[:]) {
		return ErrInvalidCertificateId
	}

	// Verify that the private key matches the public key in the certificate and the key lengths are sufficient
	switch priv := cert.Key.(type) {
	case *rsa.PrivateKey:
		pub, ok := cert.Cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			return ErrInvalidPrivateKey
		}
		if priv.N.Cmp(pub.N) != 0 {
			return ErrInvalidPrivateKey
		}
		if priv.N.BitLen() < OptMinimumRSABits {
			return ErrKeyTooSmall
		}
	case *ecdsa.PrivateKey:
		pub, ok := cert.Cert.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return ErrInvalidPrivateKey
		}
		if priv.X.Cmp(pub.X) != 0 || priv.Y.Cmp(pub.Y) != 0 {
			return ErrInvalidPrivateKey
		}
		// TODO: Not 100% positive that this is the correct way to check key size on an eliptic curve. Needs review.
		if priv.X.BitLen() < OptMinimumECBits || priv.Y.BitLen() < OptMinimumECBits {
			return ErrKeyTooSmall
		}
	default:
		return ErrInvalidPrivateKey
	}

	return nil
}

func (cert *Certificate) GetData() *CertificateData {
	certData := &CertificateData{
		Id:     cert.Id,
		UserId: cert.UserId,
		Active: cert.Active,
	}

	// Encode the certificate
	certBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Cert.Raw,
	}
	certData.Cert = string(pem.EncodeToMemory(certBlock))

	// Encode the private key
	keyBlock := &pem.Block{}
	switch priv := cert.Key.(type) {
	case *rsa.PrivateKey:
		keyBlock.Type = "RSA PRIVATE KEY"
		keyBlock.Bytes = x509.MarshalPKCS1PrivateKey(priv)
	case *ecdsa.PrivateKey:
		keyBlock.Type = "DSA PRIVATE KEY"
		var err error
		keyBlock.Bytes, err = x509.MarshalECPrivateKey(priv)
		if err != nil {
			panic("Invalid Private Key")
		}
	default:
		panic("Invalid Private Key type")
	}
	certData.Key = string(pem.EncodeToMemory(keyBlock))

	return certData
}

func (cert *Certificate) MarshalJSON() ([]byte, error) {
	return json.Marshal(cert.GetData())
}

func (cert *Certificate) UnmarshalJSON(data []byte) error {
	certData := new(CertificateData)
	err := json.Unmarshal(data, certData)
	if err != nil {
		return err
	}
	newCert, err := NewCertificateFromData(certData)
	if err != nil {
		return err
	}

	// Copy values
	cert.Id = newCert.Id
	cert.UserId = newCert.UserId
	cert.Active = newCert.Active
	cert.Cert = newCert.Cert
	cert.Key = newCert.Key

	return nil
}

// Convert a JSON compatible PEM Block (where " " is used in lieu of "\n") to a regular PEM Block
// It also checks to make sure there is only one PEM Block defined per string
func PEMBlockNormalize(jsonpem string) ([]byte, error) {
	parts := strings.Split(jsonpem, "-----")
	if len(parts) != 5 {
		return nil, ErrInvalidPEMBlock // Too many PEM Blocks, or malformed PEM Block
	}
	parts[2] = strings.Replace(parts[2], " ", "\n", -1)
	return []byte(strings.Join(parts, "-----")), nil
}
