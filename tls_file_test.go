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
	"context"
	"crypto/tls"
	"os"
	"slices"
	"testing"
	"time"
)

func TestWatchCertFile(t *testing.T) {
	certfile := "_test_cert_file.pem"
	keyfile := "_test_key_file.pem"

	if err := os.WriteFile(certfile, []byte(Cert), 0600); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(certfile)

	if err := os.WriteFile(keyfile, []byte(Key), 0600); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(keyfile)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	var cert *tls.Certificate
	WatchCertFiles(ctx, nil, time.Millisecond*500, certfile, keyfile, func(c *tls.Certificate) {
		cert = c
	})

	if cert == nil {
		t.Fatal("expect a certificate, but got none")
	}

	if !slices.Contains(cert.Leaf.DNSNames, "localhost") {
		t.Errorf("expect to contain SNI, but got not: %v", cert.Leaf.DNSNames)
	}

	if cn := cert.Leaf.Subject.CommonName; cn != "test" {
		t.Errorf("execpt CN '%s', but got '%s'", "test", cn)
	}
}
