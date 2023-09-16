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
	"time"
)

func TestCertIsValid(t *testing.T) {
	cert, err := tls.X509KeyPair([]byte(Cert), []byte(Key))
	if err != nil {
		t.Fatal(err)
	}

	if CertIsValid(&cert, time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Error("expect invalid, but got valid")
	}
	if !CertIsValid(&cert, time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Error("expect valid, but got invalid")
	}
	if CertIsValid(&cert, time.Date(3000, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Error("expect invalid, but got valid")
	}

	cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}

	if CertIsValid(&cert, time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Error("expect invalid, but got valid")
	}
	if !CertIsValid(&cert, time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Error("expect valid, but got invalid")
	}
	if CertIsValid(&cert, time.Date(3000, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Error("expect invalid, but got valid")
	}
}
