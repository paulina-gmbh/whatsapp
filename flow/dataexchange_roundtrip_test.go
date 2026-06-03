package flow_test

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/piusalfred/whatsapp/flow"
)

// TestDataExchangeRoundTrip exercises the full encrypted data-exchange path the
// way Meta's client does it: AES-128-GCM with a 16-byte IV, AES key wrapped with
// RSA-OAEP/SHA-256, and the response decrypted with the same key and the
// bitwise-flipped IV. It is a regression guard for two bugs:
//   - aesGCM{Decrypt,Encrypt} must accept Meta's 16-byte IV (not Go's 12-byte
//     GCM default), otherwise Open/Seal panic on every real request;
//   - DecryptRequest must return the RSA-decrypted AES key, otherwise
//     EncryptResponse feeds the RSA ciphertext to aes.NewCipher.
func TestDataExchangeRoundTrip(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	loader := func(context.Context) (*rsa.PrivateKey, error) { return key, nil }
	handler := flow.DataExchangeHandlerFunc(func(_ context.Context, req *flow.DataExchangeRequest) (*flow.Response, error) {
		if req.Action == "ping" {
			return flow.CreateHealthCheckResponse("active"), nil
		}
		return flow.CreateErrorAcknowledgmentResponse(true), nil
	})
	impl := flow.NewDataExchangeHandler(loader, handler)

	srv := httptest.NewServer(http.HandlerFunc(impl.Handle))
	defer srv.Close()

	aesKey := make([]byte, 16)
	if _, err := rand.Read(aesKey); err != nil {
		t.Fatalf("aes key: %v", err)
	}
	iv := make([]byte, 16)
	if _, err := rand.Read(iv); err != nil {
		t.Fatalf("iv: %v", err)
	}

	plaintext, err := json.Marshal(map[string]any{"version": "3.0", "action": "ping"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, len(iv))
	if err != nil {
		t.Fatalf("gcm: %v", err)
	}
	sealed := gcm.Seal(nil, iv, plaintext, nil)

	encAESKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &key.PublicKey, aesKey, nil)
	if err != nil {
		t.Fatalf("rsa encrypt: %v", err)
	}

	reqBody, err := json.Marshal(flow.Request{
		EncryptedFlowData: base64.StdEncoding.EncodeToString(sealed),
		EncryptedAesKey:   base64.StdEncoding.EncodeToString(encAESKey),
		InitialVector:     base64.StdEncoding.EncodeToString(iv),
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	resp, err := http.Post(srv.URL, "application/json", strings.NewReader(string(reqBody)))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	raw, err := base64.StdEncoding.DecodeString(string(body))
	if err != nil {
		t.Fatalf("decode response: %v", err)
	}

	flipped := make([]byte, len(iv))
	for i, b := range iv {
		flipped[i] = b ^ 0xFF
	}
	out, err := gcm.Open(nil, flipped, raw, nil)
	if err != nil {
		t.Fatalf("decrypt response: %v", err)
	}

	var decoded struct {
		Data struct {
			Status string `json:"status"`
		} `json:"data"`
	}
	if err := json.Unmarshal(out, &decoded); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if decoded.Data.Status != "active" {
		t.Fatalf("status: got %q, want active", decoded.Data.Status)
	}
}
