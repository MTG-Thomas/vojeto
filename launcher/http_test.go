//go:build linux

package launcher

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func certificate(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, usage x509.ExtKeyUsage) (tls.Certificate, *x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	serial, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if e != nil {
		t.Fatal(e)
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "test"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	if ca == nil {
		template.IsCA = true
		template.BasicConstraintsValid = true
		template.KeyUsage |= x509.KeyUsageCertSign
		ca = template
		caKey = key
	}
	der, e := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if e != nil {
		t.Fatal(e)
	}
	parsed, e := x509.ParseCertificate(der)
	if e != nil {
		t.Fatal(e)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, parsed, key
}
func TestMutuallyAuthenticatedHTTP(t *testing.T) {
	m, e := Open(context.Background(), configuration(t))
	if e != nil {
		t.Fatal(e)
	}
	defer m.Close()
	_, ca, key := certificate(t, nil, nil, x509.ExtKeyUsageAny)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	server, _, _ := certificate(t, ca, key, x509.ExtKeyUsageServerAuth)
	broker, brokerLeaf, _ := certificate(t, ca, key, x509.ExtKeyUsageClientAuth)
	other, _, _ := certificate(t, ca, key, x509.ExtKeyUsageClientAuth)
	hash := sha256.Sum256(brokerLeaf.Raw)
	tlsConfig, e := TLS(server, pool, hex.EncodeToString(hash[:]))
	if e != nil {
		t.Fatal(e)
	}
	endpoint := httptest.NewUnstartedServer(Handler(m))
	endpoint.TLS = tlsConfig
	endpoint.StartTLS()
	defer endpoint.Close()
	for name, clientCert := range map[string][]tls.Certificate{"missing": nil, "other trusted client": {other}} {
		t.Run(name, func(t *testing.T) {
			client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, Certificates: clientCert, MinVersion: tls.VersionTLS13}}, Timeout: time.Second}
			defer client.CloseIdleConnections()
			resp, e := client.Get(endpoint.URL + "/v1/sessions/00000000000000000000000000000000")
			if e == nil {
				resp.Body.Close()
				t.Fatal("unapproved broker reached API")
			}
		})
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, Certificates: []tls.Certificate{broker}, MinVersion: tls.VersionTLS13}}, Timeout: 5 * time.Second}
	defer client.CloseIdleConnections()
	r, _, _ := request(t)
	b, _ := json.Marshal(r)
	resp, e := client.Post(endpoint.URL+"/v1/sessions", "application/json", bytes.NewReader(b))
	if e != nil {
		t.Fatal(e)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("create: %d", resp.StatusCode)
	}
	var session Session
	if json.NewDecoder(resp.Body).Decode(&session) != nil || session.ID != r.ID {
		t.Fatal("invalid response")
	}
	req, _ := http.NewRequest(http.MethodDelete, endpoint.URL+"/v1/sessions/"+r.ID, nil)
	resp, e = client.Do(req)
	if e != nil {
		t.Fatal(e)
	}
	resp.Body.Close()
	if resp.StatusCode != 204 {
		t.Fatalf("stop: %d", resp.StatusCode)
	}
	resp, e = client.Post(endpoint.URL+"/v1/sessions", "application/json", bytes.NewReader(b))
	if e != nil {
		t.Fatal(e)
	}
	resp.Body.Close()
	if resp.StatusCode != 410 {
		t.Fatalf("replayed grant: %d", resp.StatusCode)
	}
	resp, e = client.Post(endpoint.URL+"/v1/sessions", "application/json", bytes.NewBufferString(`{"unknown":1}`))
	if e != nil {
		t.Fatal(e)
	}
	resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Fatal("unknown fields accepted")
	}
	// Public Handler cannot accidentally serve this capability over plaintext.
	recorder := httptest.NewRecorder()
	Handler(m).ServeHTTP(recorder, httptest.NewRequest("POST", "/v1/sessions", bytes.NewReader(b)))
	if recorder.Code != 401 {
		t.Fatal("plaintext accepted")
	}
}
