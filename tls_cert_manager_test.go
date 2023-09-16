// Copyright 2023 xgfone
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tlsx

import (
	"crypto/tls"
	"crypto/x509"
	"testing"
)

func TestCertManager(t *testing.T) {
	m := NewCertManager()

	_ = m.ClietConfig(nil)
	_ = m.ServerConfig(nil)

	if certs := m.Gets(); certs != nil {
		t.Error("expect a nil, but got a certificate slice")
	}

	cert1 := new(tls.Certificate)
	cert2 := new(tls.Certificate)
	cert3 := new(tls.Certificate)

	m.Add("cert1", cert1)
	m.Adds(map[string]*tls.Certificate{"cert2": cert2, "cert3": cert3})
	m.Adds(nil)

	m.Del("")
	m.Dels()
	m.Del("cert")
	m.Dels("cert")
	m.Del("cert1")
	if m.Get("cert1") != nil {
		t.Error("unexpect to get cert1, but got it")
	}
	if _len := m.Len(); _len != 2 {
		t.Errorf("expect %d certificates, but got %d", 2, _len)
	}
	m.Range(func(name string, _ *tls.Certificate) {
		switch name {
		case "cert2", "cert3":
		default:
			t.Errorf("unexpect certificate '%s'", name)
		}
	})

	m.Dels("cert2", "cert3")
	if _len := m.Len(); _len != 0 {
		t.Errorf("expect %d certificates, but got %d", 0, _len)
	}
	if _len := len(m.Gets()); _len != 0 {
		t.Errorf("expect %d certificates, but got %d", 0, _len)
	}

	cert, err := tls.X509KeyPair([]byte(Cert), []byte(Key))
	if err != nil {
		t.Fatal(err)
	}
	if cert.Leaf == nil {
		cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			t.Fatal(err)
		}
	}

	m.Add("localhost", &cert)

	var ciphersuiteids []uint16
	for _, cs := range tls.CipherSuites() {
		ciphersuiteids = append(ciphersuiteids, cs.ID)
	}

	chi := &tls.ClientHelloInfo{
		ServerName:        "www.abc.com",
		CipherSuites:      ciphersuiteids,
		SupportedCurves:   []tls.CurveID{tls.CurveP256, tls.CurveP384, tls.CurveP521},
		SupportedVersions: []uint16{tls.VersionTLS11, tls.VersionTLS12, tls.VersionTLS13},
	}
	if _, err := m.GetCertificate(chi); err == nil {
		t.Error("unexpect match the certificate, but got matched")
	}

	chi.ServerName = "localhost"
	if _, err := m.GetCertificate(chi); err != nil {
		t.Error("expect match the certificate, but got not")
	}

	if _, err := m.GetClientCertificate(new(tls.CertificateRequestInfo)); err == nil {
		t.Error("expect an error, but got nil")
	}

	cri := &tls.CertificateRequestInfo{
		Version:          tls.VersionTLS12,
		AcceptableCAs:    [][]byte{cert.Leaf.RawIssuer},
		SignatureSchemes: []tls.SignatureScheme{tls.ECDSAWithSHA1, tls.PKCS1WithSHA1},
	}
	if _, err := m.GetClientCertificate(cri); err != nil {
		t.Errorf("unexpect an error, but got: %s", err)
	}
}
