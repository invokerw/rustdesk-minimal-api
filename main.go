package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const defaultAddressBookJSON = `{"tags":[],"peers":[]}`

const (
	maxBodySize     = 8 << 20
	defaultPageSize = 100
)

type config struct {
	Listen       string
	Username     string
	PasswordHash string
	DisplayName  string
	DataFile     string
	TokenTTL     time.Duration
}

type persistentState struct {
	TokenSecret          string                  `json:"token_secret"`
	TokenVersion         int64                   `json:"token_version"`
	AddressBook          string                  `json:"address_book"`
	AddressBookUpdatedAt time.Time               `json:"address_book_updated_at"`
	Devices              map[string]deviceRecord `json:"devices"`
}

type deviceRecord struct {
	ID              string     `json:"id"`
	UUID            string     `json:"uuid,omitempty"`
	Owner           string     `json:"owner"`
	DeviceGroupName string     `json:"device_group_name,omitempty"`
	Note            string     `json:"note,omitempty"`
	Info            deviceInfo `json:"info"`
	LastSeenAt      time.Time  `json:"last_seen_at"`
	LastHeartbeatAt time.Time  `json:"last_heartbeat_at,omitempty"`
	LastSysinfoAt   time.Time  `json:"last_sysinfo_at,omitempty"`
	Version         string     `json:"version,omitempty"`
}

type deviceInfo struct {
	Username   string `json:"username,omitempty"`
	DeviceName string `json:"device_name,omitempty"`
	OS         string `json:"os,omitempty"`
}

type tokenClaims struct {
	Subject string `json:"sub"`
	Expiry  int64  `json:"exp"`
	Version int64  `json:"ver"`
}

type apiServer struct {
	cfg   config
	mu    sync.Mutex
	state persistentState
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Type     string `json:"type"`
}

type loginResponse struct {
	AccessToken string      `json:"access_token"`
	Type        string      `json:"type"`
	User        userPayload `json:"user"`
}

type userPayload struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	Avatar      string `json:"avatar"`
	Email       string `json:"email"`
	Note        string `json:"note"`
	Verifier    string `json:"verifier"`
	Status      int    `json:"status"`
	IsAdmin     bool   `json:"is_admin"`
}

type addressBookResponse struct {
	Data            string    `json:"data"`
	UpdatedAt       time.Time `json:"updated_at"`
	LicensedDevices int       `json:"licensed_devices"`
}

type pageResponse[T any] struct {
	Data  []T `json:"data"`
	Total int `json:"total"`
}

type addressBookUpdateRequest struct {
	Data string `json:"data"`
}

type deviceGroupPayload struct {
	Name string `json:"name"`
}

type peerPayload struct {
	ID              string         `json:"id"`
	Info            map[string]any `json:"info"`
	Status          int            `json:"status"`
	User            string         `json:"user"`
	UserName        string         `json:"user_name"`
	DeviceGroupName string         `json:"device_group_name"`
	Note            string         `json:"note"`
}

func main() {
	cfg := loadConfig()
	server, err := newAPIServer(cfg)
	if err != nil {
		log.Fatal(err)
	}

	httpServer := &http.Server{
		Addr:              cfg.Listen,
		Handler:           server.routes(),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       30 * time.Second,
	}

	log.Printf("minimal RustDesk API server listening on %s", cfg.Listen)
	log.Printf("data file: %s", cfg.DataFile)
	log.Printf("username: %s", cfg.Username)

	if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

func loadConfig() config {
	listen := flag.String("listen", getenv("RUSTDESK_API_LISTEN", ":21114"), "listen address")
	credential := flag.String("credential", getenv("RUSTDESK_API_CREDENTIAL", ""), "single allowed account in username:bcrypt_hash format")
	displayName := flag.String("display-name", getenv("RUSTDESK_API_DISPLAY_NAME", ""), "display name returned to the client")
	dataFile := flag.String("data", getenv("RUSTDESK_API_DATA", "./state.json"), "path to the persistent state file")
	tokenTTL := flag.Duration("token-ttl", getenvDuration("RUSTDESK_API_TOKEN_TTL", 30*24*time.Hour), "issued token lifetime")
	flag.Parse()

	username, passwordHash, err := parseCredential(*credential)
	if err != nil {
		log.Fatalf("invalid credential: %v", err)
	}

	cfg := config{
		Listen:       *listen,
		Username:     username,
		PasswordHash: passwordHash,
		DisplayName:  strings.TrimSpace(*displayName),
		DataFile:     *dataFile,
		TokenTTL:     *tokenTTL,
	}
	if cfg.DisplayName == "" {
		cfg.DisplayName = cfg.Username
	}
	if cfg.TokenTTL <= 0 {
		log.Fatal("token-ttl must be greater than zero")
	}
	return cfg
}

func parseCredential(spec string) (string, string, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return "", "", errors.New("use -credential or RUSTDESK_API_CREDENTIAL with username:bcrypt_hash")
	}
	username, hash, ok := strings.Cut(spec, ":")
	username = strings.TrimSpace(username)
	hash = strings.TrimSpace(hash)
	if !ok || username == "" || hash == "" {
		return "", "", errors.New("credential must use username:bcrypt_hash format")
	}
	if _, err := bcrypt.Cost([]byte(hash)); err != nil {
		return "", "", fmt.Errorf("bcrypt hash is invalid: %w", err)
	}
	return username, hash, nil
}

func newAPIServer(cfg config) (*apiServer, error) {
	s := &apiServer{cfg: cfg}
	if err := s.loadState(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *apiServer) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/api/login-options", s.handleLoginOptions)
	mux.HandleFunc("/api/login", s.handleLogin)
	mux.HandleFunc("/api/currentUser", s.requireAuth(s.handleCurrentUser))
	mux.HandleFunc("/api/logout", s.requireAuth(s.handleLogout))
	mux.HandleFunc("/api/ab", s.requireAuth(s.handleAddressBook))
	mux.HandleFunc("/api/ab/get", s.requireAuth(s.handleLegacyAddressBookGet))
	mux.HandleFunc("/api/users", s.requireAuth(s.handleUsers))
	mux.HandleFunc("/api/peers", s.requireAuth(s.handlePeers))
	mux.HandleFunc("/api/device-group/accessible", s.requireAuth(s.handleAccessibleDeviceGroups))
	mux.HandleFunc("/api/heartbeat", s.handleHeartbeat)
	mux.HandleFunc("/api/sysinfo", s.handleSysinfo)
	return s.withCORS(mux)
}

func (s *apiServer) withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *apiServer) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, ok := bearerToken(r.Header.Get("Authorization"))
		if !ok {
			writeError(w, http.StatusUnauthorized, "Invalid token")
			return
		}
		if err := s.verifyToken(token); err != nil {
			writeError(w, http.StatusUnauthorized, "Invalid token")
			return
		}
		next(w, r)
	}
}

func (s *apiServer) handleHealthz(w http.ResponseWriter, r *http.Request) {
	if !allowMethods(w, r, http.MethodGet) {
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = io.WriteString(w, "ok\n")
}

func (s *apiServer) handleLoginOptions(w http.ResponseWriter, r *http.Request) {
	if !allowMethods(w, r, http.MethodGet) {
		return
	}
	writeJSON(w, http.StatusOK, []string{})
}

func (s *apiServer) handleLogin(w http.ResponseWriter, r *http.Request) {
	if !allowMethods(w, r, http.MethodPost) {
		return
	}

	var req loginRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Type != "" && req.Type != "account" {
		writeError(w, http.StatusBadRequest, "unsupported login type")
		return
	}
	if !s.validCredentials(strings.TrimSpace(req.Username), req.Password) {
		writeError(w, http.StatusUnauthorized, "Invalid username or password")
		return
	}

	token, err := s.issueToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to issue token")
		return
	}

	writeJSON(w, http.StatusOK, loginResponse{
		AccessToken: token,
		Type:        "access_token",
		User:        s.currentUserPayload(),
	})
}

func (s *apiServer) handleCurrentUser(w http.ResponseWriter, r *http.Request) {
	if !allowMethods(w, r, http.MethodPost) {
		return
	}
	writeJSON(w, http.StatusOK, s.currentUserPayload())
}

func (s *apiServer) handleLogout(w http.ResponseWriter, r *http.Request) {
	if !allowMethods(w, r, http.MethodPost) {
		return
	}
	if err := s.bumpTokenVersion(); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to logout")
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *apiServer) handleAddressBook(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.respondAddressBook(w)
	case http.MethodPost:
		var req addressBookUpdateRequest
		if err := decodeJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid request body")
			return
		}
		if !json.Valid([]byte(req.Data)) {
			writeError(w, http.StatusBadRequest, "address book data must be valid JSON")
			return
		}
		if err := s.updateAddressBook(req.Data); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to persist address book")
			return
		}
		w.WriteHeader(http.StatusOK)
	default:
		methodNotAllowed(w, http.MethodGet, http.MethodPost)
	}
}

func (s *apiServer) handleLegacyAddressBookGet(w http.ResponseWriter, r *http.Request) {
	if !allowMethods(w, r, http.MethodPost) {
		return
	}
	s.respondAddressBook(w)
}

func (s *apiServer) respondAddressBook(w http.ResponseWriter) {
	s.mu.Lock()
	resp := addressBookResponse{
		Data:            s.state.AddressBook,
		UpdatedAt:       s.state.AddressBookUpdatedAt.UTC(),
		LicensedDevices: 0,
	}
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, resp)
}

func (s *apiServer) handleUsers(w http.ResponseWriter, r *http.Request) {
	if !allowMethods(w, r, http.MethodGet) {
		return
	}
	current, pageSize := pageParams(r)
	users := []userPayload{s.currentUserPayload()}
	writeJSON(w, http.StatusOK, pageResponse[userPayload]{
		Data:  paginate(users, current, pageSize),
		Total: len(users),
	})
}

func (s *apiServer) handlePeers(w http.ResponseWriter, r *http.Request) {
	if !allowMethods(w, r, http.MethodGet) {
		return
	}
	current, pageSize := pageParams(r)
	devices := s.sortedDevices()
	peers := make([]peerPayload, 0, len(devices))
	for _, device := range devices {
		info := map[string]any{
			"device_name": firstNonEmpty(device.Info.DeviceName, device.ID),
		}
		if device.Info.Username != "" {
			info["username"] = device.Info.Username
		}
		if device.Info.OS != "" {
			info["os"] = device.Info.OS
		}
		peers = append(peers, peerPayload{
			ID:              device.ID,
			Info:            info,
			Status:          1,
			User:            s.cfg.Username,
			UserName:        s.cfg.Username,
			DeviceGroupName: device.DeviceGroupName,
			Note:            device.Note,
		})
	}
	writeJSON(w, http.StatusOK, pageResponse[peerPayload]{
		Data:  paginate(peers, current, pageSize),
		Total: len(peers),
	})
}

func (s *apiServer) handleAccessibleDeviceGroups(w http.ResponseWriter, r *http.Request) {
	if !allowMethods(w, r, http.MethodGet) {
		return
	}
	current, pageSize := pageParams(r)
	groupSet := make(map[string]struct{})
	for _, device := range s.sortedDevices() {
		if device.DeviceGroupName != "" {
			groupSet[device.DeviceGroupName] = struct{}{}
		}
	}
	groups := make([]deviceGroupPayload, 0, len(groupSet))
	for name := range groupSet {
		groups = append(groups, deviceGroupPayload{Name: name})
	}
	sort.Slice(groups, func(i, j int) bool {
		return groups[i].Name < groups[j].Name
	})
	writeJSON(w, http.StatusOK, pageResponse[deviceGroupPayload]{
		Data:  paginate(groups, current, pageSize),
		Total: len(groups),
	})
}

func (s *apiServer) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	if !allowMethods(w, r, http.MethodPost) {
		return
	}
	var req map[string]any
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := s.recordHeartbeat(req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{})
}

func (s *apiServer) handleSysinfo(w http.ResponseWriter, r *http.Request) {
	if !allowMethods(w, r, http.MethodPost) {
		return
	}
	var req map[string]any
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := s.recordSysinfo(req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = io.WriteString(w, "SYSINFO_UPDATED")
}

func (s *apiServer) currentUserPayload() userPayload {
	return userPayload{
		Name:        s.cfg.Username,
		DisplayName: s.cfg.DisplayName,
		Avatar:      "",
		Email:       "",
		Note:        "",
		Verifier:    "",
		Status:      1,
		IsAdmin:     true,
	}
}

func (s *apiServer) validCredentials(username, password string) bool {
	if subtle.ConstantTimeCompare([]byte(username), []byte(s.cfg.Username)) != 1 {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(s.cfg.PasswordHash), []byte(password)) == nil
}

func (s *apiServer) loadState() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := os.ReadFile(s.cfg.DataFile)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("read state file: %w", err)
		}
		s.state = persistentState{
			AddressBook:          defaultAddressBookJSON,
			AddressBookUpdatedAt: time.Now().UTC(),
		}
		if err := s.ensureStateDefaultsLocked(); err != nil {
			return err
		}
		return s.saveStateLocked()
	}

	if err := json.Unmarshal(data, &s.state); err != nil {
		return fmt.Errorf("parse state file: %w", err)
	}
	if err := s.ensureStateDefaultsLocked(); err != nil {
		return err
	}
	return s.saveStateLocked()
}

func (s *apiServer) ensureStateDefaultsLocked() error {
	if s.state.TokenSecret == "" {
		secret, err := randomToken(32)
		if err != nil {
			return fmt.Errorf("generate token secret: %w", err)
		}
		s.state.TokenSecret = secret
	}
	if s.state.AddressBook == "" {
		s.state.AddressBook = defaultAddressBookJSON
	}
	if !json.Valid([]byte(s.state.AddressBook)) {
		return errors.New("state address_book is not valid JSON")
	}
	if s.state.AddressBookUpdatedAt.IsZero() {
		s.state.AddressBookUpdatedAt = time.Now().UTC()
	}
	if s.state.Devices == nil {
		s.state.Devices = make(map[string]deviceRecord)
	}
	return nil
}

func (s *apiServer) saveStateLocked() error {
	if err := os.MkdirAll(filepath.Dir(s.cfg.DataFile), 0o755); err != nil {
		return fmt.Errorf("create state directory: %w", err)
	}
	payload, err := json.MarshalIndent(s.state, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal state: %w", err)
	}
	tmp := s.cfg.DataFile + ".tmp"
	if err := os.WriteFile(tmp, payload, 0o600); err != nil {
		return fmt.Errorf("write temp state file: %w", err)
	}
	if err := os.Rename(tmp, s.cfg.DataFile); err != nil {
		return fmt.Errorf("replace state file: %w", err)
	}
	return nil
}

func (s *apiServer) updateAddressBook(data string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.AddressBook = data
	s.state.AddressBookUpdatedAt = time.Now().UTC()
	return s.saveStateLocked()
}

func (s *apiServer) bumpTokenVersion() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.TokenVersion++
	return s.saveStateLocked()
}

func (s *apiServer) issueToken() (string, error) {
	s.mu.Lock()
	claims := tokenClaims{
		Subject: s.cfg.Username,
		Expiry:  time.Now().Add(s.cfg.TokenTTL).Unix(),
		Version: s.state.TokenVersion,
	}
	secret := s.state.TokenSecret
	s.mu.Unlock()

	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signature := signTokenPayload(secret, payload)
	return base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func (s *apiServer) verifyToken(token string) error {
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return errors.New("invalid token format")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return errors.New("invalid token payload")
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return errors.New("invalid token signature")
	}

	s.mu.Lock()
	secret := s.state.TokenSecret
	version := s.state.TokenVersion
	s.mu.Unlock()

	expected := signTokenPayload(secret, payload)
	if subtle.ConstantTimeCompare(signature, expected) != 1 {
		return errors.New("signature mismatch")
	}

	var claims tokenClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return errors.New("invalid claims")
	}
	if claims.Subject != s.cfg.Username {
		return errors.New("unexpected subject")
	}
	if claims.Version != version {
		return errors.New("token revoked")
	}
	if time.Now().Unix() >= claims.Expiry {
		return errors.New("token expired")
	}
	return nil
}

func (s *apiServer) recordHeartbeat(payload map[string]any) error {
	id := strings.TrimSpace(stringValue(payload["id"]))
	if id == "" {
		return errors.New("missing device id")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	device := s.getOrCreateDeviceLocked(id)
	device.UUID = firstNonEmpty(strings.TrimSpace(stringValue(payload["uuid"])), device.UUID)
	device.Version = firstNonEmpty(strings.TrimSpace(stringValue(payload["ver"])), device.Version)
	device.LastSeenAt = time.Now().UTC()
	device.LastHeartbeatAt = device.LastSeenAt
	s.state.Devices[id] = device
	return s.saveStateLocked()
}

func (s *apiServer) recordSysinfo(payload map[string]any) error {
	id := strings.TrimSpace(stringValue(payload["id"]))
	if id == "" {
		return errors.New("missing device id")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	device := s.getOrCreateDeviceLocked(id)
	device.UUID = firstNonEmpty(strings.TrimSpace(stringValue(payload["uuid"])), device.UUID)
	device.Version = firstNonEmpty(
		strings.TrimSpace(stringValue(payload["version"])),
		strings.TrimSpace(stringValue(payload["ver"])),
		device.Version,
	)
	device.Info.Username = firstNonEmpty(
		strings.TrimSpace(stringValue(payload["username"])),
		strings.TrimSpace(stringValue(payload["device_username"])),
		device.Info.Username,
	)
	device.Info.DeviceName = firstNonEmpty(
		strings.TrimSpace(stringValue(payload["hostname"])),
		strings.TrimSpace(stringValue(payload["device_name"])),
		device.Info.DeviceName,
		device.ID,
	)
	device.Info.OS = firstNonEmpty(strings.TrimSpace(stringValue(payload["os"])), device.Info.OS)
	device.DeviceGroupName = firstNonEmpty(strings.TrimSpace(stringValue(payload["device_group_name"])), device.DeviceGroupName)
	device.Note = firstNonEmpty(strings.TrimSpace(stringValue(payload["note"])), device.Note)
	device.LastSeenAt = time.Now().UTC()
	device.LastSysinfoAt = device.LastSeenAt
	s.state.Devices[id] = device
	return s.saveStateLocked()
}

func (s *apiServer) getOrCreateDeviceLocked(id string) deviceRecord {
	device, ok := s.state.Devices[id]
	if !ok {
		device = deviceRecord{
			ID:    id,
			Owner: s.cfg.Username,
			Info: deviceInfo{
				DeviceName: id,
			},
		}
	}
	if device.Owner == "" {
		device.Owner = s.cfg.Username
	}
	if device.Info.DeviceName == "" {
		device.Info.DeviceName = id
	}
	return device
}

func (s *apiServer) sortedDevices() []deviceRecord {
	s.mu.Lock()
	defer s.mu.Unlock()

	devices := make([]deviceRecord, 0, len(s.state.Devices))
	for _, device := range s.state.Devices {
		devices = append(devices, device)
	}
	sort.Slice(devices, func(i, j int) bool {
		if devices[i].LastSeenAt.Equal(devices[j].LastSeenAt) {
			return devices[i].ID < devices[j].ID
		}
		return devices[i].LastSeenAt.After(devices[j].LastSeenAt)
	})
	return devices
}

func signTokenPayload(secret string, payload []byte) []byte {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	return mac.Sum(nil)
}

func randomToken(size int) (string, error) {
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func bearerToken(header string) (string, bool) {
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return "", false
	}
	token := strings.TrimSpace(strings.TrimPrefix(header, prefix))
	return token, token != ""
}

func allowMethods(w http.ResponseWriter, r *http.Request, methods ...string) bool {
	for _, method := range methods {
		if r.Method == method {
			return true
		}
	}
	methodNotAllowed(w, methods...)
	return false
}

func methodNotAllowed(w http.ResponseWriter, methods ...string) {
	w.Header().Set("Allow", strings.Join(methods, ", ")+", OPTIONS")
	writeError(w, http.StatusMethodNotAllowed, "method not allowed")
}

func decodeJSON(r *http.Request, dst any) error {
	defer r.Body.Close()
	dec := json.NewDecoder(io.LimitReader(r.Body, maxBodySize))
	if err := dec.Decode(dst); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("unexpected trailing data")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("write response failed: %v", err)
	}
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func pageParams(r *http.Request) (int, int) {
	current := 1
	if value := strings.TrimSpace(r.URL.Query().Get("current")); value != "" {
		if parsed, err := strconv.Atoi(value); err == nil && parsed > 0 {
			current = parsed
		}
	}
	pageSize := defaultPageSize
	if value := strings.TrimSpace(r.URL.Query().Get("pageSize")); value != "" {
		if parsed, err := strconv.Atoi(value); err == nil && parsed > 0 {
			pageSize = parsed
		}
	}
	return current, pageSize
}

func paginate[T any](items []T, current, pageSize int) []T {
	if pageSize <= 0 {
		return items
	}
	start := (current - 1) * pageSize
	if start >= len(items) {
		return []T{}
	}
	end := start + pageSize
	if end > len(items) {
		end = len(items)
	}
	return items[start:end]
}

func stringValue(v any) string {
	switch value := v.(type) {
	case nil:
		return ""
	case string:
		return value
	case fmt.Stringer:
		return value.String()
	case json.Number:
		return value.String()
	case float64:
		return strconv.FormatInt(int64(value), 10)
	case float32:
		return strconv.FormatInt(int64(value), 10)
	case int:
		return strconv.Itoa(value)
	case int8:
		return strconv.FormatInt(int64(value), 10)
	case int16:
		return strconv.FormatInt(int64(value), 10)
	case int32:
		return strconv.FormatInt(int64(value), 10)
	case int64:
		return strconv.FormatInt(value, 10)
	case uint:
		return strconv.FormatUint(uint64(value), 10)
	case uint8:
		return strconv.FormatUint(uint64(value), 10)
	case uint16:
		return strconv.FormatUint(uint64(value), 10)
	case uint32:
		return strconv.FormatUint(uint64(value), 10)
	case uint64:
		return strconv.FormatUint(value, 10)
	case bool:
		return strconv.FormatBool(value)
	default:
		return fmt.Sprint(value)
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func getenv(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func getenvDuration(key string, fallback time.Duration) time.Duration {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	duration, err := time.ParseDuration(value)
	if err != nil {
		log.Printf("invalid duration in %s=%q, using default %s", key, value, fallback)
		return fallback
	}
	return duration
}
