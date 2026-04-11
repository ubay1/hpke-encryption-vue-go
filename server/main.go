package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"strconv"
	"strings"

	"filippo.io/hpke"
)

// ─── HPKE Suite ───────────────────────────────────────────────

var hpkeKDF = hpke.HKDFSHA256()
var hpkeAEAD = hpke.AES128GCM()

// ─── Key Storage ──────────────────────────────────────────────

type KeyPair struct {
	PublicKey  []byte `json:"publicKey"`
	PrivateKey []byte `json:"privateKey"`
}

var serverKeyPair *KeyPair

const keyFile = "server-keys-hpke.json"

func loadKeyPair() *KeyPair {
	data, err := os.ReadFile(keyFile)
	if err != nil {
		return nil
	}
	var kp KeyPair
	if err := json.Unmarshal(data, &kp); err != nil {
		return nil
	}
	return &kp
}

func saveKeyPair(kp *KeyPair) error {
	data, err := json.MarshalIndent(kp, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(keyFile, data, 0644)
}

func generateKeyPair() (*KeyPair, error) {
	privateKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}

	publicKeyBytes := privateKey.PublicKey().Bytes()
	privateKeyBytes := privateKey.Bytes()

	kp := &KeyPair{
		PublicKey:  publicKeyBytes,
		PrivateKey: privateKeyBytes,
	}

	if err := saveKeyPair(kp); err != nil {
		return nil, fmt.Errorf("save key: %w", err)
	}

	return kp, nil
}

func initKeyPair() error {
	existing := loadKeyPair()
	if existing != nil {
		serverKeyPair = existing
		log.Println("✅ Loaded existing HPKE key pair from disk")
		return nil
	}

	kp, err := generateKeyPair()
	if err != nil {
		return err
	}
	serverKeyPair = kp
	log.Println("✅ Generated new HPKE key pair and saved to disk")
	return nil
}

// ─── Helpers ──────────────────────────────────────────────────

func b64Encode(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

func b64Decode(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

// Base64url encoding for JWK (no padding, URL-safe)
func b64urlEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func b64urlDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// ─── Seal/Unseal Wrapper Functions ────────────────────────────

const wrapperLength = 5

func isBase64String(str string) bool {
	notBase64 := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
	for _, c := range str {
		if !strings.ContainsRune(notBase64, c) {
			return false
		}
	}
	if len(str)%4 != 0 {
		return false
	}
	return true
}

func generateWrapperString() string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	result := make([]byte, wrapperLength)
	for i := range result {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		result[i] = charset[n.Int64()]
	}
	return string(result)
}

func wrapBase64(base64Str string) string {
	prefix := generateWrapperString()
	suffix := prefix

	// Remove padding from base64
	base64WithoutPadding := strings.TrimRight(base64Str, "=")
	paddingCount := len(base64Str) - len(base64WithoutPadding)

	// Format: prefix + base64WithoutPadding + suffix + paddingCount
	return fmt.Sprintf("%s%s%s%d", prefix, base64WithoutPadding, suffix, paddingCount)
}

func unwrapBase64(str string) string {
	strLength := len(str)

	if strLength < wrapperLength*2+2 {
		return str
	}

	// Extract prefix (first 5 chars)
	prefix := str[0:wrapperLength]

	// Extract suffix (5 chars before the last digit)
	suffix := str[strLength-wrapperLength-1 : strLength-1]

	// Extract padding count (last digit)
	paddingCountStr := str[strLength-1:]
	paddingCount, err := strconv.Atoi(paddingCountStr)
	if err != nil {
		return str
	}

	// Validate prefix matches suffix
	if prefix == suffix {
		// Extract base64 (between prefix and suffix)
		base64WithoutPadding := str[wrapperLength : strLength-wrapperLength-1]

		// Add padding back
		padding := strings.Repeat("=", paddingCount)
		return base64WithoutPadding + padding
	}

	return str
}

// ─── HPKE Encrypt/Decrypt ─────────────────────────────────────

func hpkeEncrypt(plaintext []byte, recipientPublicKeyBytes []byte) (ciphertext []byte, enc []byte, err error) {
	recipientPub, err := ecdh.P256().NewPublicKey(recipientPublicKeyBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("import public key: %w", err)
	}

	dhkemPub, err := hpke.NewDHKEMPublicKey(recipientPub)
	if err != nil {
		return nil, nil, fmt.Errorf("create DHKEM public key: %w", err)
	}

	enc, sender, err := hpke.NewSender(dhkemPub, hpkeKDF, hpkeAEAD, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("create sender: %w", err)
	}

	ciphertext, err = sender.Seal(nil, plaintext)
	if err != nil {
		return nil, nil, fmt.Errorf("seal: %w", err)
	}

	return ciphertext, enc, nil
}

func hpkeDecrypt(ciphertext []byte, enc []byte, privateKeyBytes []byte) ([]byte, error) {
	privateKey, err := ecdh.P256().NewPrivateKey(privateKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("import private key: %w", err)
	}

	dhkemPriv, err := hpke.NewDHKEMPrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("create DHKEM private key: %w", err)
	}

	recipient, err := hpke.NewRecipient(enc, dhkemPriv, hpkeKDF, hpkeAEAD, nil)
	if err != nil {
		return nil, fmt.Errorf("create recipient: %w", err)
	}

	plaintext, err := recipient.Open(nil, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("open: %w", err)
	}

	return plaintext, nil
}

// ─── HPKE Seal/Unseal (Wrapped Format) ────────────────────────

/**
 * Seal: Encrypt and return a wrapped base64 string
 * Format: prefix + base64(headerSize + header + ciphertext + enc) + suffix + paddingCount
 */
func hpkeSeal(plaintext []byte, recipientPublicKeyBytes []byte) (string, error) {
	ciphertext, enc, err := hpkeEncrypt(plaintext, recipientPublicKeyBytes)
	if err != nil {
		return "", err
	}

	// Create header with ciphertext length
	headerStr := strconv.Itoa(len(ciphertext))
	header := []byte(headerStr)

	// Build combined payload: [headerSize][header][ciphertext][enc]
	combined := make([]byte, 0, 1+len(header)+len(ciphertext)+len(enc))
	combined = append(combined, byte(len(header)))
	combined = append(combined, header...)
	combined = append(combined, ciphertext...)
	combined = append(combined, enc...)

	// Encode to base64 and wrap
	base64Result := base64.StdEncoding.EncodeToString(combined)
	wrappedResult := wrapBase64(base64Result)

	return wrappedResult, nil
}

/**
 * Unseal: Decrypt a wrapped base64 string back to plaintext
 */
func hpkeUnseal(wrappedCipher string, privateKeyBytes []byte) ([]byte, error) {
	unwrappedCipher := unwrapBase64(wrappedCipher)

	if !isBase64String(unwrappedCipher) {
		return nil, fmt.Errorf("invalid wrapped cipher format")
	}

	combined, err := base64.StdEncoding.DecodeString(unwrappedCipher)
	if err != nil {
		return nil, fmt.Errorf("decode base64: %w", err)
	}

	if len(combined) < 1 {
		return nil, fmt.Errorf("empty combined data")
	}

	// Parse header
	headerSize := int(combined[0])
	if len(combined) < 1+headerSize {
		return nil, fmt.Errorf("invalid header size")
	}

	cipherSize, err := strconv.Atoi(string(combined[1 : 1+headerSize]))
	if err != nil {
		return nil, fmt.Errorf("parse cipher size: %w", err)
	}

	cipherStart := 1 + headerSize
	cipherEnd := cipherStart + cipherSize

	if cipherEnd > len(combined) {
		return nil, fmt.Errorf("invalid ciphertext boundaries")
	}

	ciphertext := combined[cipherStart:cipherEnd]
	enc := combined[cipherEnd:]

	// Decrypt
	return hpkeDecrypt(ciphertext, enc, privateKeyBytes)
}

// ─── Request/Response Types ───────────────────────────────────

type ApiRequest struct {
	Data               string          `json:"data,omitempty"`
	RecipientPublicKey json.RawMessage `json:"recipientPublicKey,omitempty"`
	ClientPublicKey    json.RawMessage `json:"clientPublicKey,omitempty"`
}

type ApiResponse struct {
	Data string `json:"data"`
}

// ─── Helpers for Key Parsing ──────────────────────────────────

// Parse public key from JWK or base64 string
func parsePublicKey(raw json.RawMessage) ([]byte, error) {
	// Try as base64 string first
	var str string
	if err := json.Unmarshal(raw, &str); err == nil {
		decoded, err := b64Decode(str)
		if err == nil {
			// Try to parse as JWK
			var jwk map[string]interface{}
			if err := json.Unmarshal(decoded, &jwk); err == nil {
				return parseJWK(jwk)
			}
			// Try as raw bytes (33 bytes compressed or 65 bytes uncompressed)
			if len(decoded) == 33 || len(decoded) == 65 {
				return decoded, nil
			}
		}
		return nil, fmt.Errorf("invalid base64 string")
	}

	// Try as JWK object
	var jwk map[string]interface{}
	if err := json.Unmarshal(raw, &jwk); err != nil {
		return nil, fmt.Errorf("invalid key format")
	}

	return parseJWK(jwk)
}

func parseJWK(jwk map[string]interface{}) ([]byte, error) {
	xStr, ok := jwk["x"].(string)
	if !ok {
		return nil, fmt.Errorf("missing x coordinate")
	}
	yStr, ok := jwk["y"].(string)
	if !ok {
		return nil, fmt.Errorf("missing y coordinate")
	}

	x, err := b64urlDecode(xStr)
	if err != nil {
		return nil, fmt.Errorf("decode x: %w", err)
	}
	y, err := b64urlDecode(yStr)
	if err != nil {
		return nil, fmt.Errorf("decode y: %w", err)
	}

	// Construct uncompressed point (0x04 || x || y)
	point := make([]byte, 1+len(x)+len(y))
	point[0] = 0x04
	copy(point[1:], x)
	copy(point[1+len(x):], y)

	return point, nil
}

func publicKeyToJWK(publicKeyBytes []byte) map[string]interface{} {
	// Try to decompress if needed
	var xBytes, yBytes []byte

	if len(publicKeyBytes) == 65 && publicKeyBytes[0] == 0x04 {
		// Already uncompressed
		xBytes = publicKeyBytes[1:33]
		yBytes = publicKeyBytes[33:65]
	} else if len(publicKeyBytes) == 33 {
		// Compressed - decompress using elliptic curve
		curve := elliptic.P256()
		x, y := elliptic.UnmarshalCompressed(curve, publicKeyBytes)
		if x == nil {
			return nil
		}
		xBytes = x.Bytes()
		yBytes = y.Bytes()

		// Pad to 32 bytes if needed
		for len(xBytes) < 32 {
			xBytes = append([]byte{0}, xBytes...)
		}
		for len(yBytes) < 32 {
			yBytes = append([]byte{0}, yBytes...)
		}
	} else {
		return nil
	}

	return map[string]interface{}{
		"kty": "EC",
		"crv": "P-256",
		"x":   b64urlEncode(xBytes),
		"y":   b64urlEncode(yBytes),
		"ext": true,
	}
}

// ─── HTTP Handlers ────────────────────────────────────────────

func handleRoot(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"message": "HPKE Encryption Server (Go)"})
}

func handlePublicKey(w http.ResponseWriter, r *http.Request) {
	if serverKeyPair == nil {
		if err := initKeyPair(); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}

	// Get uncompressed public key (raw format for seal)
	pubKeyBytes := serverKeyPair.PublicKey
	if len(pubKeyBytes) == 33 {
		// Decompress if needed
		curve := elliptic.P256()
		x, y := elliptic.UnmarshalCompressed(curve, pubKeyBytes)
		if x != nil {
			// Build uncompressed point
			uncompressed := make([]byte, 1, 1+len(x.Bytes())+len(y.Bytes()))
			uncompressed[0] = 0x04
			uncompressed = append(uncompressed, x.Bytes()...)
			uncompressed = append(uncompressed, y.Bytes()...)
			pubKeyBytes = uncompressed
		}
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"data": b64Encode(pubKeyBytes),
	})
}

func handleEncrypt(w http.ResponseWriter, r *http.Request) {
	var req ApiRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Data == "" || len(req.RecipientPublicKey) == 0 {
		writeError(w, http.StatusBadRequest, "Missing 'data' or 'recipientPublicKey'")
		return
	}

	pubKeyBytes, err := parsePublicKey(req.RecipientPublicKey)
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid public key: %v", err))
		return
	}

	ciphertext, enc, err := hpkeEncrypt([]byte(req.Data), pubKeyBytes)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("Encryption failed: %v", err))
		return
	}

	combined, _ := json.Marshal(map[string]string{
		"ciphertext": b64Encode(ciphertext),
		"enc":        b64Encode(enc),
	})

	writeJSON(w, http.StatusOK, ApiResponse{
		Data: b64Encode(combined),
	})
}

func handleSeal(w http.ResponseWriter, r *http.Request) {
	var req ApiRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if serverKeyPair == nil {
		writeError(w, http.StatusBadRequest, "Server key pair not initialized")
		return
	}

	// If data is provided, unseal it and return the decrypted data (re-data)
	if req.Data != "" {
		// Unseal the data
		combinedPayload, err := hpkeUnseal(req.Data, serverKeyPair.PrivateKey)
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("Failed to unseal data: %v", err))
			return
		}

		// Parse combined JSON: { "data": "...", "publicKey": "..." }
		var payload struct {
			Data      string `json:"data"`
			PublicKey string `json:"publicKey"`
		}
		if err := json.Unmarshal(combinedPayload, &payload); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid payload format: %v", err))
			return
		}

		if payload.Data == "" {
			writeError(w, http.StatusBadRequest, "Missing 'data' in payload")
			return
		}

		if payload.PublicKey == "" {
			writeError(w, http.StatusBadRequest, "Missing 'publicKey' in payload")
			return
		}

		// Parse client JWK and convert to raw uncompressed point
		var jwk map[string]interface{}
		jwkJSON, _ := b64Decode(payload.PublicKey)
		if err := json.Unmarshal(jwkJSON, &jwk); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid client JWK: %v", err))
			return
		}
		pubKeyBytes, err := parseJWK(jwk)
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid client public key: %v", err))
			return
		}

		// Re-seal with client's public key
		dataResponse, err := hpkeSeal([]byte(payload.Data), pubKeyBytes)
		if err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to seal response: %v", err))
			return
		}

		writeJSON(w, http.StatusOK, map[string]string{
			"data": dataResponse,
		})
		return
	}

	// If plain data + recipientPublicKey, seal it
	if req.Data == "" || len(req.RecipientPublicKey) == 0 {
		writeError(w, http.StatusBadRequest, "Missing 'data' or 'data'+'recipientPublicKey'")
		return
	}

	pubKeyBytes, err := parsePublicKey(req.RecipientPublicKey)
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid public key: %v", err))
		return
	}

	sealed, err := hpkeSeal([]byte(req.Data), pubKeyBytes)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("Seal failed: %v", err))
		return
	}

	writeJSON(w, http.StatusOK, ApiResponse{
		Data: sealed,
	})
}

func handleUnseal(w http.ResponseWriter, r *http.Request) {
	var req ApiRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Data == "" {
		writeError(w, http.StatusBadRequest, "Missing 'data'")
		return
	}

	if serverKeyPair == nil {
		writeError(w, http.StatusBadRequest, "Server key pair not initialized")
		return
	}

	plaintext, err := hpkeUnseal(req.Data, serverKeyPair.PrivateKey)
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("Unseal failed: %v", err))
		return
	}

	writeJSON(w, http.StatusOK, ApiResponse{
		Data: string(plaintext),
	})
}

func handleDecrypt(w http.ResponseWriter, r *http.Request) {
	var req ApiRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if serverKeyPair == nil {
		writeError(w, http.StatusBadRequest, "Server key pair not initialized")
		return
	}

	if req.Data == "" {
		writeError(w, http.StatusBadRequest, "Missing 'data'")
		return
	}

	plaintext, err := hpkeUnseal(req.Data, serverKeyPair.PrivateKey)
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("Unseal failed: %v", err))
		return
	}

	writeJSON(w, http.StatusOK, ApiResponse{
		Data: string(plaintext),
	})
}

func handleServerEncrypt(w http.ResponseWriter, r *http.Request) {
	var req ApiRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if len(req.ClientPublicKey) == 0 || req.Data == "" {
		writeError(w, http.StatusBadRequest, "Missing 'data' or 'clientPublicKey'")
		return
	}

	if serverKeyPair == nil {
		writeError(w, http.StatusBadRequest, "Server key pair not initialized")
		return
	}

	// Unseal the data
	plaintext, err := hpkeUnseal(req.Data, serverKeyPair.PrivateKey)
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("Failed to unseal data: %v", err))
		return
	}

	// Parse client public key
	pubKeyBytes, err := parsePublicKey(req.ClientPublicKey)
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid client public key: %v", err))
		return
	}

	// Seal with client public key
	sealed, err := hpkeSeal(plaintext, pubKeyBytes)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("Encryption failed: %v", err))
		return
	}

	writeJSON(w, http.StatusOK, ApiResponse{
		Data: sealed,
	})
}

// ─── CORS Middleware ──────────────────────────────────────────

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "http://localhost:5173")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.Header().Set("Access-Control-Expose-Headers", "*")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// ─── Main ─────────────────────────────────────────────────────

func main() {
	// Load or generate key pair
	if err := initKeyPair(); err != nil {
		log.Fatalf("Failed to init key pair: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", handleRoot)
	mux.HandleFunc("/api/server-public-key", handlePublicKey)
	mux.HandleFunc("/api/encrypt", handleEncrypt)
	mux.HandleFunc("/api/decrypt", handleDecrypt)
	mux.HandleFunc("/api/server-encrypt", handleServerEncrypt)
	mux.HandleFunc("/api/seal", handleSeal)
	mux.HandleFunc("/api/unseal", handleUnseal)
	mux.HandleFunc("/api/external-api", handleExternalApi)

	handler := corsMiddleware(mux)

	port := "9003"
	log.Printf("HPKE Server (Go) is running on http://localhost:%s", port)

	if err := http.ListenAndServe(":"+port, handler); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

// ─── External API Proxy (Seal → BE → jsonplaceholder → Seal) ──

func handleExternalApi(w http.ResponseWriter, r *http.Request) {
	var req ApiRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Data == "" {
		writeError(w, http.StatusBadRequest, "Missing 'data'")
		return
	}

	if serverKeyPair == nil {
		writeError(w, http.StatusBadRequest, "Server key pair not initialized")
		return
	}

	// 1. Unseal client data (contains { data, publicKey })
	combinedPayload, err := hpkeUnseal(req.Data, serverKeyPair.PrivateKey)
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("Failed to unseal data: %v", err))
		return
	}

	// 2. Parse combined JSON: { "data": "...", "publicKey": "..." }
	var payload struct {
		Data      string `json:"data"`
		PublicKey string `json:"publicKey"`
	}
	if err := json.Unmarshal(combinedPayload, &payload); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid payload format: %v", err))
		return
	}

	if payload.Data == "" {
		writeError(w, http.StatusBadRequest, "Missing 'data' in payload")
		return
	}

	if payload.PublicKey == "" {
		writeError(w, http.StatusBadRequest, "Missing 'publicKey' in payload")
		return
	}

	// 3. Parse client public key
	pubKeyBytes, err := parseJWKRtoRaw(payload.PublicKey)
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid client public key: %v", err))
		return
	}

	// 4. Send data to jsonplaceholder
	var jsonPayload map[string]interface{}
	if err := json.Unmarshal([]byte(payload.Data), &jsonPayload); err == nil {
		// It's JSON, send as-is
	} else {
		// Not JSON, wrap it
		jsonPayload = map[string]interface{}{
			"title":  payload.Data,
			"body":   payload.Data,
			"userId": 1,
		}
	}

	jpReqData, _ := json.Marshal(jsonPayload)
	jpRes, err := http.Post(
		"https://jsonplaceholder.typicode.com/posts",
		"application/json",
		bytes.NewBuffer(jpReqData),
	)
	if err != nil {
		writeError(w, http.StatusBadGateway, fmt.Sprintf("Failed to call external API: %v", err))
		return
	}
	defer jpRes.Body.Close()

	jpResBody, _ := io.ReadAll(jpRes.Body)

	// 5. Seal jsonplaceholder response with client public key
	sealedResponse, err := hpkeSeal(jpResBody, pubKeyBytes)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to seal response: %v", err))
		return
	}

	writeJSON(w, http.StatusOK, ApiResponse{
		Data: sealedResponse,
	})
}

// parseJWKRtoRaw converts base64 JWK string to raw uncompressed EC point bytes
func parseJWKRtoRaw(b64Jwk string) ([]byte, error) {
	jwkJSON, _ := base64.StdEncoding.DecodeString(b64Jwk)
	var jwk map[string]interface{}
	if err := json.Unmarshal(jwkJSON, &jwk); err != nil {
		return nil, err
	}
	return parseJWK(jwk)
}
