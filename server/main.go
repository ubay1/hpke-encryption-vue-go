package main

import (
	"crypto/ecdh"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

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

// ─── Request/Response Types ───────────────────────────────────

type EncryptRequest struct {
	Data               string          `json:"data"`
	RecipientPublicKey json.RawMessage `json:"recipientPublicKey"`
}

type DecryptRequest struct {
	Encrypted  string `json:"encrypted,omitempty"`
	Ciphertext string `json:"ciphertext,omitempty"`
	Enc        string `json:"enc,omitempty"`
}

type ServerEncryptRequest struct {
	Data            string          `json:"data,omitempty"`
	EncryptedData   string          `json:"encryptedData,omitempty"`
	ClientPublicKey json.RawMessage `json:"clientPublicKey"`
}

type EncryptResponse struct {
	Encrypted string `json:"encrypted"`
}

type DecryptResponse struct {
	Data string `json:"data"`
}

type PublicKeyResponse struct {
	PublicKeyString string `json:"publicKeyString"`
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

	jwk := publicKeyToJWK(serverKeyPair.PublicKey)
	jwkJSON, _ := json.Marshal(jwk)

	writeJSON(w, http.StatusOK, PublicKeyResponse{
		PublicKeyString: b64Encode(jwkJSON),
	})
}

func handleEncrypt(w http.ResponseWriter, r *http.Request) {
	var req EncryptRequest
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

	writeJSON(w, http.StatusOK, EncryptResponse{
		Encrypted: b64Encode(combined),
	})
}

func handleDecrypt(w http.ResponseWriter, r *http.Request) {
	var req DecryptRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	ciphertextB64 := req.Ciphertext
	encB64 := req.Enc

	// Handle combined encrypted string
	if req.Encrypted != "" && (req.Ciphertext == "" || req.Enc == "") {
		combined, err := b64Decode(req.Encrypted)
		if err != nil {
			writeError(w, http.StatusBadRequest, "Invalid encrypted string")
			return
		}

		var parsed map[string]string
		if err := json.Unmarshal(combined, &parsed); err != nil {
			writeError(w, http.StatusBadRequest, "Invalid encrypted format")
			return
		}

		ciphertextB64 = parsed["ciphertext"]
		encB64 = parsed["enc"]
	}

	if ciphertextB64 == "" || encB64 == "" {
		writeError(w, http.StatusBadRequest, "Missing 'ciphertext', 'enc', or 'encrypted'")
		return
	}

	if serverKeyPair == nil {
		writeError(w, http.StatusBadRequest, "Server key pair not initialized")
		return
	}

	ciphertext, err := b64Decode(ciphertextB64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid ciphertext")
		return
	}

	enc, err := b64Decode(encB64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid enc")
		return
	}

	plaintext, err := hpkeDecrypt(ciphertext, enc, serverKeyPair.PrivateKey)
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("Decryption failed: %v", err))
		return
	}

	writeJSON(w, http.StatusOK, DecryptResponse{
		Data: string(plaintext),
	})
}

func handleServerEncrypt(w http.ResponseWriter, r *http.Request) {
	var req ServerEncryptRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if len(req.ClientPublicKey) == 0 {
		writeError(w, http.StatusBadRequest, "Missing 'clientPublicKey'")
		return
	}

	// If encryptedData provided, decrypt it first
	var plaintext string
	if req.EncryptedData != "" {
		if serverKeyPair == nil {
			writeError(w, http.StatusBadRequest, "Server key pair not initialized")
			return
		}

		// Parse encryptedData
		combined, err := b64Decode(req.EncryptedData)
		if err != nil {
			writeError(w, http.StatusBadRequest, "Invalid encryptedData")
			return
		}

		var parsed map[string]string
		if err := json.Unmarshal(combined, &parsed); err != nil {
			writeError(w, http.StatusBadRequest, "Invalid encryptedData format")
			return
		}

		ciphertext, err := b64Decode(parsed["ciphertext"])
		if err != nil {
			writeError(w, http.StatusBadRequest, "Invalid ciphertext in encryptedData")
			return
		}

		enc, err := b64Decode(parsed["enc"])
		if err != nil {
			writeError(w, http.StatusBadRequest, "Invalid enc in encryptedData")
			return
		}

		decrypted, err := hpkeDecrypt(ciphertext, enc, serverKeyPair.PrivateKey)
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("Failed to decrypt encryptedData: %v", err))
			return
		}

		plaintext = string(decrypted)
	} else if req.Data != "" {
		plaintext = req.Data
	} else {
		writeError(w, http.StatusBadRequest, "Missing 'data' or 'encryptedData'")
		return
	}

	// Parse client public key
	pubKeyBytes, err := parsePublicKey(req.ClientPublicKey)
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid client public key: %v", err))
		return
	}

	// Encrypt with client public key
	ciphertext, enc, err := hpkeEncrypt([]byte(plaintext), pubKeyBytes)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("Encryption failed: %v", err))
		return
	}

	combined, _ := json.Marshal(map[string]string{
		"ciphertext": b64Encode(ciphertext),
		"enc":        b64Encode(enc),
	})

	writeJSON(w, http.StatusOK, EncryptResponse{
		Encrypted: b64Encode(combined),
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
	mux.HandleFunc("/api/public-key", handlePublicKey)
	mux.HandleFunc("/api/encrypt", handleEncrypt)
	mux.HandleFunc("/api/decrypt", handleDecrypt)
	mux.HandleFunc("/api/server-encrypt", handleServerEncrypt)

	handler := corsMiddleware(mux)

	port := "9003"
	log.Printf("HPKE Server (Go) is running on http://localhost:%s", port)

	if err := http.ListenAndServe(":"+port, handler); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
