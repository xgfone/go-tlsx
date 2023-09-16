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

func BenchmarkCertManagerGet(b *testing.B) {
	m := NewCertManager()
	m.Add("cert", new(tls.Certificate))

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(p *testing.PB) {
		for p.Next() {
			_ = m.Get("cert")
		}
	})
}

func BenchmarkCertManagerMatch(b *testing.B) {
	cert, err := tls.X509KeyPair([]byte(Cert), []byte(Key))
	if err != nil {
		b.Fatal(err)
	}
	if cert.Leaf == nil {
		cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			b.Fatal(err)
		}
	}

	m := NewCertManager()
	m.Add("localhost", &cert)

	var ciphersuiteids []uint16
	for _, cs := range tls.CipherSuites() {
		ciphersuiteids = append(ciphersuiteids, cs.ID)
	}

	chi := &tls.ClientHelloInfo{
		ServerName:        "localhost",
		CipherSuites:      ciphersuiteids,
		SupportedCurves:   []tls.CurveID{tls.CurveP256, tls.CurveP384, tls.CurveP521},
		SupportedVersions: []uint16{tls.VersionTLS11, tls.VersionTLS12, tls.VersionTLS13},
	}
	if _, err := m.GetCertificate(chi); err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(p *testing.PB) {
		for p.Next() {
			if c, err := m.GetCertificate(chi); err != nil {
				b.Fatal(err)
			} else if c == nil {
				b.Fatal("got a nil certificate")
			}
		}
	})
}

func BenchmarkTLSSupportsCertificate(b *testing.B) {
	cert, err := tls.X509KeyPair([]byte(Cert), []byte(Key))
	if err != nil {
		b.Fatal(err)
	}
	if cert.Leaf == nil {
		cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			b.Fatal(err)
		}
	}
	tlscert := &cert

	var ciphersuiteids []uint16
	for _, cs := range tls.CipherSuites() {
		ciphersuiteids = append(ciphersuiteids, cs.ID)
	}
	chi := &tls.ClientHelloInfo{
		ServerName:        "localhost",
		CipherSuites:      ciphersuiteids,
		SupportedCurves:   []tls.CurveID{tls.CurveP256, tls.CurveP384, tls.CurveP521},
		SupportedVersions: []uint16{tls.VersionTLS11, tls.VersionTLS12, tls.VersionTLS13},
	}

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(p *testing.PB) {
		for p.Next() {
			if err := chi.SupportsCertificate(tlscert); err != nil {
				b.Fatal(err)
			}
		}
	})
}
