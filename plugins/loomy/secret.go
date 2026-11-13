package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sync"
)

// Local password storage.
//
// The plaintext is kept only in memory. Encode writes `password_enc` (AES-256-GCM
// with a plugin-local 0600 key file). If the key file cannot be created, Encode
// falls back to a plaintext `password` field and relies on the auth-file mode
// 0600 as the minimum protection the host allows us to apply.
//
// The key never leaves this process: it is not written into the credential,
// not logged, and not returned on management pages.

const (
	passwordEncPrefix = "v1:"
	credentialKeyName = "credential.key"
	credentialKeyPerm = 0o600
	credentialDirPerm = 0o700
)

var (
	keyMu       sync.Mutex
	keyPathOver string
	cachedKey   []byte
)

// setCredentialKeyFile pins the key file path. Tests use a temp directory so
// they cannot touch a real operator key.
func setCredentialKeyFile(path string) {
	keyMu.Lock()
	defer keyMu.Unlock()
	keyPathOver = path
	cachedKey = nil
}

func credentialKeyPath() string {
	if keyPathOver != "" {
		return keyPathOver
	}
	if cfg := settings(); cfg.CredentialKeyFile != "" {
		return cfg.CredentialKeyFile
	}
	dir, errDir := os.UserConfigDir()
	if errDir != nil || dir == "" {
		dir = os.TempDir()
	}
	return filepath.Join(dir, "loomy-provider", credentialKeyName)
}

func loadOrCreateCredentialKey() ([]byte, error) {
	keyMu.Lock()
	defer keyMu.Unlock()
	if len(cachedKey) == 32 {
		return cachedKey, nil
	}
	path := credentialKeyPath()
	if raw, errRead := os.ReadFile(path); errRead == nil && len(raw) == 32 {
		cachedKey = append([]byte(nil), raw...)
		_ = os.Chmod(path, credentialKeyPerm)
		return cachedKey, nil
	}
	key := make([]byte, 32)
	if _, errRand := io.ReadFull(rand.Reader, key); errRand != nil {
		return nil, errRand
	}
	if errMk := os.MkdirAll(filepath.Dir(path), credentialDirPerm); errMk != nil {
		return nil, errMk
	}
	// 0600 before the bytes land on disk: OpenFile applies the mode on create.
	file, errOpen := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, credentialKeyPerm)
	if errOpen != nil {
		// A concurrent creator won: read what they wrote.
		if raw, errRead := os.ReadFile(path); errRead == nil && len(raw) == 32 {
			cachedKey = append([]byte(nil), raw...)
			return cachedKey, nil
		}
		return nil, errOpen
	}
	_, errWrite := file.Write(key)
	_ = file.Chmod(credentialKeyPerm)
	errClose := file.Close()
	if errWrite != nil {
		return nil, errWrite
	}
	if errClose != nil {
		return nil, errClose
	}
	cachedKey = append([]byte(nil), key...)
	return cachedKey, nil
}

// encryptPassword returns a `v1:`-prefixed ciphertext, or an error when the
// key file cannot be used.
func encryptPassword(plaintext string) (string, error) {
	if plaintext == "" {
		return "", nil
	}
	key, errKey := loadOrCreateCredentialKey()
	if errKey != nil {
		return "", errKey
	}
	block, errBlock := aes.NewCipher(key)
	if errBlock != nil {
		return "", errBlock
	}
	gcm, errGCM := cipher.NewGCM(block)
	if errGCM != nil {
		return "", errGCM
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, errRand := io.ReadFull(rand.Reader, nonce); errRand != nil {
		return "", errRand
	}
	sealed := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return passwordEncPrefix + base64.StdEncoding.EncodeToString(sealed), nil
}

// decryptPassword reverses encryptPassword. An empty or unknown payload is
// returned as an empty string so a credential without a password still parses.
func decryptPassword(ciphertext string) (string, error) {
	if ciphertext == "" {
		return "", nil
	}
	raw := ciphertext
	if len(raw) >= len(passwordEncPrefix) && raw[:len(passwordEncPrefix)] == passwordEncPrefix {
		raw = raw[len(passwordEncPrefix):]
	}
	sealed, errDecode := base64.StdEncoding.DecodeString(raw)
	if errDecode != nil {
		return "", errDecode
	}
	key, errKey := loadOrCreateCredentialKey()
	if errKey != nil {
		return "", errKey
	}
	block, errBlock := aes.NewCipher(key)
	if errBlock != nil {
		return "", errBlock
	}
	gcm, errGCM := cipher.NewGCM(block)
	if errGCM != nil {
		return "", errGCM
	}
	if len(sealed) < gcm.NonceSize() {
		return "", transportError("bad_password_enc", "password_enc 过短")
	}
	nonce, payload := sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():]
	plain, errOpen := gcm.Open(nil, nonce, payload, nil)
	if errOpen != nil {
		return "", errOpen
	}
	return string(plain), nil
}

// chmodCredentialFile sets 0600 on a path the host just wrote, ignoring
// errors: the host owns the directory and may refuse the chmod.
func chmodCredentialFile(path string) {
	if path == "" {
		return
	}
	_ = os.Chmod(path, credentialKeyPerm)
}

// insertJSONString adds a top-level string field to a JSON object. Used only
// as the encryption-failed fallback so a password can still be persisted.
func insertJSONString(raw []byte, key, value string) []byte {
	var object map[string]any
	if json.Unmarshal(raw, &object) != nil || object == nil {
		return raw
	}
	object[key] = value
	out, errMarshal := json.Marshal(object)
	if errMarshal != nil {
		return raw
	}
	return out
}
