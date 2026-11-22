package httpserver

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"link_ping_prometheus/internal/filetrust"
	"log/slog"
	"os"
	"runtime"
	"sync"
	"time"
)

// certReloadRetryCooldown is how long a fingerprint whose load FAILED is
// skipped before the pair is read again. The retry is what makes an in-place
// repair observable: a pair fixed without touching (mtime, size) — a
// chmod-only fix, a same-size rewrite that preserves the timestamp — keeps the
// fingerprint the failed attempt was recorded under, so a pure memo would serve
// the expired certificate until the files changed again, i.e. exactly the
// silent scrape blackout the reloader exists to prevent. The cooldown keeps the
// other side of that tradeoff: a genuinely broken renewal costs one file read
// (and at most one Warn) per cooldown, not one per handshake. A var so tests
// can lower it.
var certReloadRetryCooldown = 30 * time.Second

// metricsCertReloader serves the metrics TLS pair from a cache that is re-read
// when either file's (mtime, size) changes, so a renewed certificate takes
// effect without a restart. ServeTLS otherwise loads the pair exactly once: on
// 90-day certificates plus a service that is never restarted, that one-shot load
// is a silent scrape blackout the day the cert expires — and under the SCM the
// resulting handshake error is invisible (stderr is discarded). Set as
// TLSConfig.GetCertificate, which crypto/tls consults for every handshake.
type metricsCertReloader struct {
	certPath, keyPath string

	reloadMu sync.Mutex // serializes disk reads/parses during an actual renewal
	mu       sync.Mutex // guards the cached snapshot below without holding I/O
	// cert is the pair currently served. Seeded at construction, so no
	// handshake can ever observe an empty cache.
	cert *tls.Certificate
	// loaded is the fingerprint of the pair in cert; attempted/attemptedAt are
	// the last fingerprint a reload was tried for and when. Kept apart so a
	// failed load is retried only after certReloadRetryCooldown rather than on
	// every handshake, which would flood the very log the reload exists to make
	// visible (see certReloadRetryCooldown for why the retry matters at all).
	loaded, attempted certFingerprint
	attemptedAt       time.Time
	// statFailed latches the stat-error warning the same way.
	statFailed bool
}

// maxTLSFileSize bounds a metrics TLS file. A PEM pair is a few KiB; the cap
// stops a non-regular or runaway object from being read into memory.
const maxTLSFileSize = 1 << 20

// LoadPair reads and validates the metrics TLS pair with the same
// provenance rule the targets file and the log sink use. tls.LoadX509KeyPair
// cannot be used directly: it re-resolves both paths by name with no type,
// ownership or mode check, so a symlink at either path is followed, a FIFO
// blocks the caller inside the reloader mutex, and a group/world-readable key
// is accepted silently. Here the Lstat decision is bound to the descriptor
// actually read, and the key must not be world- or group-readable.
func LoadPair(certPath, keyPath string) (tls.Certificate, error) {
	certPEM, err := readTrustedPairFile(certPath, false)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("certificate: %w", err)
	}
	keyPEM, err := readTrustedPairFile(keyPath, true)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("key: %w", err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, err
	}
	return cert, nil
}

func readTrustedPairFile(path string, secret bool) ([]byte, error) {
	opts := filetrust.TrustOptions{DenyForeignWrite: true, DenyForeignRead: secret}
	data, fi, err := filetrust.ReadFileWith(path, maxTLSFileSize, opts)
	if err != nil {
		return nil, err
	}
	if runtime.GOOS != "windows" {
		perm := fi.Mode().Perm()
		if perm&0o022 != 0 || (secret && perm&0o044 != 0) {
			return nil, fmt.Errorf("TLS file %q mode %04o exposes the pair: another local user could read the private key or replace it", path, perm)
		}
	}
	return data, nil
}

// certFingerprint identifies a certificate/key file pair by the metadata a
// renewal changes. Hashing the contents would cost a full read on every
// handshake; (mtime, size) is what rotators and `mv` in place actually touch.
type certFingerprint struct {
	certMod, keyMod   time.Time
	certSize, keySize int64
}

func fingerprintCertPair(certPath, keyPath string) (certFingerprint, error) {
	certInfo, err := os.Stat(certPath)
	if err != nil {
		return certFingerprint{}, err
	}
	keyInfo, err := os.Stat(keyPath)
	if err != nil {
		return certFingerprint{}, err
	}
	return certFingerprint{
		certMod: certInfo.ModTime(), certSize: certInfo.Size(),
		keyMod: keyInfo.ModTime(), keySize: keyInfo.Size(),
	}, nil
}

// newMetricsCertReloader loads the pair once and seeds the cache with it — the
// same load run() performs as startup validation. A pair that will not load is
// a startup error, never a listener that serves nothing.
func newMetricsCertReloader(certPath, keyPath string) (*metricsCertReloader, error) {
	// Stat BEFORE loading so a rotation occurring mid-load produces a
	// mismatching fingerprint on the next handshake instead of freezing the
	// older certificate under the newer fingerprint.
	fp, err := fingerprintCertPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	cert, err := LoadPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	return &metricsCertReloader{certPath: certPath, keyPath: keyPath, cert: &cert, loaded: fp, attempted: fp}, nil
}

// cachedIfFresh returns the cached certificate if fp matches the currently
// loaded pair or a recently failed reload inside certReloadRetryCooldown.
func (r *metricsCertReloader) cachedIfFresh(fp certFingerprint) (*tls.Certificate, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if fp == r.loaded || (fp == r.attempted && time.Since(r.attemptedAt) < certReloadRetryCooldown) {
		return r.cert, true
	}
	return r.cert, false
}

// GetCertificate implements tls.Config.GetCertificate.
func (r *metricsCertReloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.Lock()
	cachedCert := r.cert
	wasStatFailed := r.statFailed
	r.mu.Unlock()

	fp, err := fingerprintCertPair(r.certPath, r.keyPath)
	if err != nil {
		// Keep serving the cached pair during transient rename/stat gaps.
		if !wasStatFailed {
			r.mu.Lock()
			first := !r.statFailed
			r.statFailed = true
			cachedCert = r.cert
			r.mu.Unlock()
			if first {
				slog.Warn("Metrics TLS certificate files are not statable; keeping the previously loaded certificate",
					"cert", r.certPath, "key", r.keyPath, "err", err)
			}
		}
		return cachedCert, nil
	}
	if wasStatFailed {
		r.mu.Lock()
		r.statFailed = false
		r.mu.Unlock()
	}
	if cert, ok := r.cachedIfFresh(fp); ok {
		return cert, nil
	}

	r.reloadMu.Lock()
	defer r.reloadMu.Unlock()

	fp, err = fingerprintCertPair(r.certPath, r.keyPath)
	if err != nil {
		r.mu.Lock()
		cachedCert = r.cert
		r.mu.Unlock()
		return cachedCert, nil
	}
	if cert, ok := r.cachedIfFresh(fp); ok {
		return cert, nil
	}

	cert, err := LoadPair(r.certPath, r.keyPath)
	now := time.Now()
	r.mu.Lock()
	r.attempted, r.attemptedAt = fp, now
	if err != nil {
		cachedCert = r.cert
		r.mu.Unlock()
		// A half-written renewal or a key that does not match: keep the working
		// cert and say so once. Failing the handshake instead would black out
		// every scrape over a transient write.
		slog.Warn("Metrics TLS certificate reload failed; keeping the previously loaded certificate",
			"cert", r.certPath, "key", r.keyPath, "err", err)
		return cachedCert, nil
	}
	r.cert, r.loaded = &cert, fp
	r.mu.Unlock()

	// Log the served leaf so a substitution is distinguishable from a
	// renewal: two reload lines naming only the paths look identical.
	cn, serial := "", ""
	if len(cert.Certificate) > 0 {
		if leaf, err := x509.ParseCertificate(cert.Certificate[0]); err == nil {
			cn, serial = leaf.Subject.CommonName, leaf.SerialNumber.String()
		}
	}
	slog.Info("Metrics TLS certificate reloaded", "cert", r.certPath, "key", r.keyPath, "cn", cn, "serial", serial)
	return &cert, nil
}
