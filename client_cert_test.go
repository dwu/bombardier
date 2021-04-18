package main

import (
	"testing"
)

func TestGenerateTLSConfig(t *testing.T) {
	expectations := []struct {
		certPath string
		keyPath  string
		errIsNil bool
	}{
		{
			certPath: "testclient.cert",
			keyPath:  "testclient.key",
			errIsNil: true,
		},
		{
			certPath: "doesnotexist.pem",
			keyPath:  "doesnotexist.pem",
			errIsNil: false,
		},
		{
			certPath: "",
			keyPath:  "",
			errIsNil: true,
		},
	}
	for _, e := range expectations {
		_, r := generateTLSConfig(
			config{
				url:      "https://doesnt.exist.com",
				certPath: e.certPath,
				keyPath:  e.keyPath,
			},
		)
		if (r == nil) != e.errIsNil {
			t.Error(e.certPath, e.keyPath, r)
		}
	}
}

func TestGenerateTLSConfigWithCaCert(t *testing.T) {
	expectations := []struct {
		caCertPath string
		errIsNil   bool
	}{
		{
			caCertPath: "testclient.cert",
			errIsNil:   true,
		},
		{
			caCertPath: "doesnotexist.pem",
			errIsNil:   false,
		},
	}
	for _, e := range expectations {
		_, r := generateTLSConfig(
			config{
				url:        "https://doesnt.exist.com",
				caCertPath: e.caCertPath,
			},
		)
		if (r == nil) != e.errIsNil {
			t.Error(e.caCertPath, r)
		}
	}
}
