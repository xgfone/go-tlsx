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
	"crypto/x509"
	"log/slog"
	"time"
)

// Getter is used to get the changed data.
// Return (nil, false, nil) if not changed.
type Getter func() (data []byte, changed bool, err error)

// WatchCert watches the change of the certificate,
// reloads and parses them as TLS X509 certificate,
// then calls the callback function with it.
func WatchCert(ctx context.Context, reload <-chan struct{}, interval time.Duration,
	name string, getcert, getkey Getter, cb func(name string, cert *tls.Certificate)) {

	if getcert == nil {
		panic("the getcert function must not be nil")
	}
	if getkey == nil {
		panic("the getkey function must not be nil")
	}
	if cb == nil {
		panic("the callback function must not be nil")
	}

	if interval <= 0 {
		interval = time.Minute
	}

	checkAndLoadCert(name, getcert, getkey, cb)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return

		case <-reload:
			checkAndLoadCert(name, getcert, getkey, cb)

		case <-ticker.C:
			checkAndLoadCert(name, getcert, getkey, cb)
		}
	}
}

func checkAndLoadCert(name string, getcert, getkey Getter, cb func(string, *tls.Certificate)) {
	certdata, certchanged, err := getcert()
	if err != nil {
		slog.Error("fail to load the certificate", "name", name, "err", err)
		return
	}

	keydata, keychanged, err := getkey()
	if err != nil {
		slog.Error("fail to load the certificate key", "name", name, "err", err)
		return
	}

	if !certchanged && !keychanged {
		return
	}

	tlscert, err := tls.X509KeyPair(certdata, keydata)
	if err != nil {
		slog.Error("invalid certificate", "name", name, "err", err)
		return
	}

	if tlscert.Leaf == nil {
		tlscert.Leaf, err = x509.ParseCertificate(tlscert.Certificate[0])
		if err != nil {
			slog.Error("invalid leaf certificate", "name", name, "err", err)
			return
		}
	}

	cb(name, &tlscert)
}
