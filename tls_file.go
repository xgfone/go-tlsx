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
	"io"
	"log/slog"
	"os"
	"time"
)

// WatchCertFiles watches the change of the certificate files,
// reloads and parses them as TLS X509 certificate,
// then calls the callback function with it.
func WatchCertFiles(ctx context.Context, reload <-chan struct{},
	interval time.Duration, certfile, keyfile string, cb func(*tls.Certificate)) {

	if certfile == "" {
		panic("the cert file must not be empty")
	}
	if keyfile == "" {
		panic("the key file must not be empty")
	}
	if cb == nil {
		panic("the callback function must not be nil")
	}

	if interval <= 0 {
		interval = time.Minute
	}

	key := &fileinfo{file: keyfile}
	cert := &fileinfo{file: certfile}

	checkAndLoadCertFiles(cert, key, cb)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return

		case <-reload:
			checkAndLoadCertFiles(cert, key, cb)

		case <-ticker.C:
			checkAndLoadCertFiles(cert, key, cb)
		}
	}
}

type fileinfo struct {
	file string
	data []byte
	size int64
	last int64
}

func checkAndLoadCertFiles(cert, key *fileinfo, cb func(*tls.Certificate)) {
	changed1, err := checkAndLoadCertFile(cert)
	if err != nil {
		slog.Error("fail to check or load the certificate file",
			slog.String("certfile", cert.file), slog.String("err", err.Error()))
		return
	}

	changed2, err := checkAndLoadCertFile(key)
	if err != nil {
		slog.Error("fail to check or load the certificate key file",
			slog.String("keyfile", cert.file), slog.String("err", err.Error()))
		return
	}

	if !changed1 && !changed2 {
		return
	}

	tlscert, err := tls.X509KeyPair(cert.data, key.data)
	if err != nil {
		slog.Error("invalid certificate files", slog.String("keyfile", key.file),
			slog.String("certfile", cert.file), slog.String("err", err.Error()))
		return
	}

	if tlscert.Leaf == nil {
		tlscert.Leaf, err = x509.ParseCertificate(tlscert.Certificate[0])
		if err != nil {
			slog.Error("invalid leaf certificate", slog.String("keyfile", key.file),
				slog.String("certfile", cert.file), slog.String("err", err.Error()))
			return
		}
	}

	cb(&tlscert)
}

func checkAndLoadCertFile(fi *fileinfo) (changed bool, err error) {
	file, err := os.Open(fi.file)
	if err != nil {
		return
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return
	}

	modtime := info.ModTime().Unix()
	if modtime == fi.last && info.Size() == fi.size {
		return
	}

	fi.data, err = io.ReadAll(file)
	if err != nil {
		return
	}

	fi.size = info.Size()
	fi.last = modtime
	changed = true
	return
}
