package main

import (
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
)

// readClientCert - helper function to read client certificate
// from pem formatted certPath and keyPath files
func readClientCert(certPath, keyPath string) ([]tls.Certificate, error) {
	// load keypair
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	return []tls.Certificate{cert}, err
}

// readCaCert - helper function to read a client certificate from
// pem formatted caCertPath and add it to the system cert pool
func readCaCert(caCertPath string) (*x509.CertPool, error) {
	caCert, err := ioutil.ReadFile(caCertPath)
	if err != nil {
		return nil, err
	}

	caCertPool, _ := x509.SystemCertPool()
	if err != nil {
		return nil, err
	}

	ok := caCertPool.AppendCertsFromPEM(caCert)
	if !ok {
		return nil, err
	}

	return caCertPool, nil
}

// generateTLSConfig - helper function to generate a TLS configuration based on
// config
func generateTLSConfig(c config) (*tls.Config, error) {
	var (
		certs []tls.Certificate
		err   error
	)
	// This assumes that the caller has validated that either both or none of
	// the c.certPath and c.keyPath are set.
	if c.certPath != "" && c.keyPath != "" {
		certs, err = readClientCert(c.certPath, c.keyPath)
		if err != nil {
			return nil, err
		}
	}

	// Disable gas warning, because InsecureSkipVerify may be set to true
	// for the purpose of testing
	/* #nosec */
	tlsConfig := &tls.Config{
		InsecureSkipVerify: c.insecure,
		Certificates:       certs,
	}

	if c.caCertPath != "" {
		caCertPool, err := readCaCert(c.caCertPath)
		if err != nil {
			return nil, err
		} else {
			tlsConfig.RootCAs = caCertPool
			return tlsConfig, nil
		}
	}

	return tlsConfig, nil
}
