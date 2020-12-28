package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"math/big"
	"net"
	"sync"
	"time"

	"github.com/pion/dtls/v2"
)

func newCertificate(key crypto.PrivateKey, tpl x509.Certificate) (*x509.Certificate, error) {
	var err error
	var certDER []byte
	switch sk := key.(type) {
	case *rsa.PrivateKey:
		pk := sk.Public()
		tpl.SignatureAlgorithm = x509.SHA256WithRSA
		certDER, err = x509.CreateCertificate(rand.Reader, &tpl, &tpl, pk, sk)
		if err != nil {
			return nil, err
		}
	case *ecdsa.PrivateKey:
		pk := sk.Public()
		tpl.SignatureAlgorithm = x509.ECDSAWithSHA256
		certDER, err = x509.CreateCertificate(rand.Reader, &tpl, &tpl, pk, sk)
		if err != nil {
			return nil, err
		}
	default:
		return nil, err
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

type DTLSConnection struct {
	lock sync.RWMutex
	conn *dtls.Conn

	inConn  net.Conn
	outConn net.Conn

	privateKey crypto.PrivateKey
	x509Cert   *x509.Certificate
}

func (d *DTLSConnection) GenerateCertificate() {

	secretKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	if err != nil {
		panic(err)
	}

	origin := make([]byte, 16)

	_, err = rand.Read(origin)

	if err != nil {
		panic(err)
	}

	// Max random value, a 130-bits integer, i.e 2^130 - 1
	maxBigInt := new(big.Int)
	/* #nosec */
	maxBigInt.Exp(big.NewInt(2), big.NewInt(130), nil).Sub(maxBigInt, big.NewInt(1))
	/* #nosec */
	serialNumber, err := rand.Int(rand.Reader, maxBigInt)
	if err != nil {
		panic(err)
	}

	certificate := x509.Certificate{
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageServerAuth,
		},
		BasicConstraintsValid: true,
		NotBefore:             time.Now(),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		NotAfter:              time.Now().AddDate(0, 1, 0),
		SerialNumber:          serialNumber,
		Version:               2,
		Subject:               pkix.Name{CommonName: hex.EncodeToString(origin)},
		IsCA:                  true,
	}

	x509Cert, err := newCertificate(secretKey, certificate)

	d.privateKey = secretKey
	d.x509Cert = x509Cert
}

func (d *DTLSConnection) Start() (err error) {

	var dtlsConn *dtls.Conn

	dtlsConfig := &dtls.Config{
		Certificates: []tls.Certificate{
			{
				Certificate: [][]byte{d.x509Cert.Raw},
				PrivateKey:  d.privateKey,
			},
		},
		SRTPProtectionProfiles: []dtls.SRTPProtectionProfile{dtls.SRTP_AES128_CM_HMAC_SHA1_80},
		ClientAuth:             dtls.RequireAnyClientCert,
		InsecureSkipVerify:     true,
	}

	d.inConn, d.outConn = net.Pipe()
	dtlsConn, err = dtls.Server(d.inConn, dtlsConfig)
	d.conn = dtlsConn

	srtpProfile, ok := dtlsConn.SelectedSRTPProtectionProfile()
	if !ok {
		fmt.Println("error :", srtpProfile)
	}
	return
}

func main() {

	fmt.Println("test")

	s, _ := net.ResolveUDPAddr("udp4", ":4444")
	conn, err := net.ListenUDP("udp4", s)
	if err != nil {
		panic(err)
	}

	dtlsConn := new(DTLSConnection)
	dtlsConn.GenerateCertificate()
	err = dtlsConn.Start()
	if err != nil {
		panic(err)
	}

	buffers := make(chan []byte, 10)

	go func() {
		b := make([]byte, 2048)
		for {
			n, err := dtlsConn.outConn.Read(b)
			if err != nil {
				panic(err)
			}
			buffers <- b[:n]
		}
	}()

	buffer := make([]byte, 2048)

	for {
		n, addr, err := conn.ReadFrom(buffer)
		if err != nil {
			break
		}

		dtlsConn.outConn.Write(buffer[:n])

		select {
		case b := <-buffers:
			conn.WriteTo(b, addr)
		default:
			fmt.Println("can not get buffer")
		}
	}

}
