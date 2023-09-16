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
	"time"
)

// CertIsValid reports whether the certificate is valid.
//
// if now is ZERO, use time.Now() instead.
func CertIsValid(cert *tls.Certificate, now time.Time) bool {
	x509cert := cert.Leaf
	if x509cert == nil {
		if len(cert.Certificate) == 0 {
			return false
		}

		var err error
		x509cert, err = x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return false
		}
	}

	if now.IsZero() {
		now = time.Now().UTC()
	}
	return now.After(x509cert.NotBefore) && now.Before(x509cert.NotAfter)
}
