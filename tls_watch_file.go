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
	"io"
	"os"
	"time"
)

// WatchCertFile watches the change of the certificate files,
// reloads and parses them as TLS X509 certificate,
// then calls the callback function with it.
func WatchCertFile(ctx context.Context, reload <-chan struct{}, interval time.Duration,
	certfile, keyfile string, cb func(*tls.Certificate)) {
	cbf := func(_ string, cert *tls.Certificate) { cb(cert) }
	WatchCert(ctx, reload, interval, certfile, fromfile(certfile), fromfile(keyfile), cbf)
}

func fromfile(file string) Getter {
	var lastsize, lasttime int64
	return func() (data []byte, changed bool, err error) {
		f, err := os.Open(file)
		if err != nil {
			return
		}
		defer f.Close()

		info, err := f.Stat()
		if err != nil {
			return
		}

		modtime := info.ModTime().Unix()
		if modtime == lasttime && info.Size() == lastsize {
			return
		}

		data, err = io.ReadAll(f)
		if err != nil {
			return
		}

		lastsize = info.Size()
		lasttime = modtime
		changed = true
		return
	}
}
