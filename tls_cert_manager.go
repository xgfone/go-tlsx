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
	"errors"
	"fmt"
	"maps"
	"sync"
	"sync/atomic"
)

// DefaultCertManager is the default certificate manager.
var DefaultCertManager = NewCertManager()

var nocert = errors.New("chain is not signed by an acceptable CA")

type certwrapper struct{ Certificates []*tls.Certificate }

// CertManager is used to manage a set of tls certificates, which is thread-safe.
type CertManager struct {
	lock  sync.RWMutex
	certm map[string]*tls.Certificate
	certs atomic.Pointer[certwrapper]
}

// NewCertManager returns a new certificate manager.
func NewCertManager() *CertManager {
	m := &CertManager{certm: make(map[string]*tls.Certificate, 4)}
	m.certs.Store(new(certwrapper))
	return m
}

func (m *CertManager) updatecerts() {
	w := m.certs.Load()
	w.Certificates = mapvalues(m.certm)
	m.certs.Store(w)
}

// Add adds the tls certificate with the name.
//
// If exists, override it.
func (m *CertManager) Add(name string, cert *tls.Certificate) {
	if name == "" {
		panic("tlsx.CertManager.Add: the cert name must not be empty")
	}
	if cert == nil {
		panic("tlsx.CertManager.Add: the cert must not be nil")
	}

	m.lock.Lock()
	m.certm[name] = cert
	m.updatecerts()
	m.lock.Unlock()
}

// Adds adds a set of certificates with the names.
//
// If exists, override it.
func (m *CertManager) Adds(certm map[string]*tls.Certificate) {
	if len(certm) == 0 {
		return
	}

	m.lock.Lock()
	maps.Copy(m.certm, certm)
	m.updatecerts()
	m.lock.Unlock()
}

// Del deletes the tls certificate by the name.
//
// If not exist, do nothing.
func (m *CertManager) Del(name string) {
	if name == "" {
		return
	}

	m.lock.Lock()
	if _, ok := m.certm[name]; ok {
		delete(m.certm, name)
		m.updatecerts()
	}
	m.lock.Unlock()
}

// Dels deletes a set of tls certificates by the names.
//
// If not exist, ignore it.
func (m *CertManager) Dels(names ...string) {
	if len(names) == 0 {
		return
	}

	m.lock.Lock()
	var changed bool
	for _, name := range names {
		if _, ok := m.certm[name]; ok {
			delete(m.certm, name)
			changed = true
		}
	}
	if changed {
		m.updatecerts()
	}
	m.lock.Unlock()
}

// Len returns the number of all the tls certificates.
func (m *CertManager) Len() int {
	return len(m.certs.Load().Certificates)
}

// Get returns the tls certificate by the name.
//
// If not exist, return nil.
func (m *CertManager) Get(name string) *tls.Certificate {
	m.lock.RLock()
	cert := m.certm[name]
	m.lock.RUnlock()
	return cert
}

// Gets returns the list of all the tls certificates.
func (m *CertManager) Gets() []*tls.Certificate {
	return m.certs.Load().Certificates
}

// Range ranges all the tls certificates.
//
// If not need name, Gets should be used preferentially,
// because Gets is lockless and Range is locked.
func (m *CertManager) Range(f func(name string, cert *tls.Certificate)) {
	m.lock.RLock()
	defer m.lock.RUnlock()
	for name, cert := range m.certm {
		f(name, cert)
	}
}

// GetCertificate ranges all the certificates and one by one tries to
// match the tls handshake information from the client until found,
// which is used to be assigned to tls.Config.GetCertificate.
func (m *CertManager) GetCertificate(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
	for _, cert := range m.Gets() {
		if chi.SupportsCertificate(cert) == nil {
			return cert, nil
		}
	}
	return nil, fmt.Errorf("tls: no proper certificate is configured for '%s'", chi.ServerName)
}

// GetClientCertificate ranges all the certificates and one by one tries to
// match the tls certificate request information from the server until found,
// which is used to be assigned to tls.Config.GetClientCertificate.
func (m *CertManager) GetClientCertificate(cri *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	for _, cert := range m.Gets() {
		if cri.SupportsCertificate(cert) == nil {
			return cert, nil
		}
	}
	return nil, nocert
}

// ClietConfig sets the client certificate get function of c and return itself.
//
// If c is nil, clone DefaultTLSConfig and use it instead.
func (m *CertManager) ClietConfig(c *tls.Config) *tls.Config {
	if c == nil {
		c = DefaultTLSConfig.Clone()
	}

	c.GetClientCertificate = m.GetClientCertificate
	return c
}

// ServerConfig sets the server certificate get function of c and return itself.
//
// If c is nil, clone DefaultTLSConfig and use it instead.
func (m *CertManager) ServerConfig(c *tls.Config) *tls.Config {
	if c == nil {
		c = DefaultTLSConfig.Clone()
	}

	c.GetCertificate = m.GetCertificate
	return c
}
