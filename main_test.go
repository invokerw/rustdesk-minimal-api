package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func TestLoginAndAddressBookFlow(t *testing.T) {
	t.Parallel()

	server := newTestServer(t)
	handler := server.routes()

	token := loginForToken(t, handler)

	resp := doRequest(t, handler, http.MethodPost, "/api/currentUser", nil, token)
	if resp.Code != http.StatusOK {
		t.Fatalf("currentUser status = %d, want %d", resp.Code, http.StatusOK)
	}
	var user userPayload
	decodeResponse(t, resp, &user)
	if user.Name != server.cfg.Username {
		t.Fatalf("user.Name = %q, want %q", user.Name, server.cfg.Username)
	}

	resp = doRequest(t, handler, http.MethodGet, "/api/ab", nil, token)
	if resp.Code != http.StatusOK {
		t.Fatalf("get /api/ab status = %d, want %d", resp.Code, http.StatusOK)
	}
	var initial addressBookResponse
	decodeResponse(t, resp, &initial)
	if initial.Data != defaultAddressBookJSON {
		t.Fatalf("initial address book = %s, want %s", initial.Data, defaultAddressBookJSON)
	}

	updatedAB := `{"tags":["ops"],"peers":[{"id":"123456789","alias":"demo"}]}`
	resp = doRequest(t, handler, http.MethodPost, "/api/ab", addressBookUpdateRequest{Data: updatedAB}, token)
	if resp.Code != http.StatusOK {
		t.Fatalf("post /api/ab status = %d, want %d", resp.Code, http.StatusOK)
	}
	if resp.Body.Len() != 0 {
		t.Fatalf("post /api/ab body = %q, want empty", resp.Body.String())
	}

	resp = doRequest(t, handler, http.MethodPost, "/api/ab/get", map[string]any{}, token)
	if resp.Code != http.StatusOK {
		t.Fatalf("post /api/ab/get status = %d, want %d", resp.Code, http.StatusOK)
	}
	var legacy addressBookResponse
	decodeResponse(t, resp, &legacy)
	if legacy.Data != updatedAB {
		t.Fatalf("legacy address book = %s, want %s", legacy.Data, updatedAB)
	}

	resp = doRequest(t, handler, http.MethodGet, "/api/users", nil, token)
	if resp.Code != http.StatusOK {
		t.Fatalf("get /api/users status = %d, want %d", resp.Code, http.StatusOK)
	}
	var page pageResponse[userPayload]
	decodeResponse(t, resp, &page)
	if page.Total != 1 || len(page.Data) != 1 || page.Data[0].Name != server.cfg.Username {
		t.Fatalf("users page = %#v, want one user %q", page, server.cfg.Username)
	}
}

func TestAccessibleDevicesInventoryFromSysinfoAndHeartbeat(t *testing.T) {
	t.Parallel()

	server := newTestServer(t)
	handler := server.routes()

	resp := doRequest(t, handler, http.MethodPost, "/api/sysinfo", map[string]any{
		"id":                "123456789",
		"uuid":              "uuid-1",
		"hostname":          "workstation-01",
		"username":          "alice-pc",
		"os":                "Linux / Ubuntu 24.04",
		"device_group_name": "Servers",
		"note":              "Lab box",
		"version":           "1.3.9",
	}, "")
	if resp.Code != http.StatusOK {
		t.Fatalf("sysinfo status = %d, want %d: %s", resp.Code, http.StatusOK, resp.Body.String())
	}
	if body := resp.Body.String(); body != "SYSINFO_UPDATED" {
		t.Fatalf("sysinfo body = %q, want %q", body, "SYSINFO_UPDATED")
	}

	resp = doRequest(t, handler, http.MethodPost, "/api/heartbeat", map[string]any{
		"id":   "222222222",
		"uuid": "uuid-2",
		"ver":  169,
	}, "")
	if resp.Code != http.StatusOK {
		t.Fatalf("heartbeat status = %d, want %d: %s", resp.Code, http.StatusOK, resp.Body.String())
	}

	token := loginForToken(t, handler)

	resp = doRequest(t, handler, http.MethodGet, "/api/device-group/accessible", nil, token)
	if resp.Code != http.StatusOK {
		t.Fatalf("device-group status = %d, want %d", resp.Code, http.StatusOK)
	}
	var groups pageResponse[deviceGroupPayload]
	decodeResponse(t, resp, &groups)
	if groups.Total != 1 || len(groups.Data) != 1 || groups.Data[0].Name != "Servers" {
		t.Fatalf("groups = %#v, want single Servers group", groups)
	}

	resp = doRequest(t, handler, http.MethodGet, "/api/peers", nil, token)
	if resp.Code != http.StatusOK {
		t.Fatalf("peers status = %d, want %d", resp.Code, http.StatusOK)
	}
	var peers pageResponse[peerPayload]
	decodeResponse(t, resp, &peers)
	if peers.Total != 2 || len(peers.Data) != 2 {
		t.Fatalf("peers = %#v, want two devices", peers)
	}

	indexed := make(map[string]peerPayload, len(peers.Data))
	for _, peer := range peers.Data {
		indexed[peer.ID] = peer
	}

	sysinfoPeer, ok := indexed["123456789"]
	if !ok {
		t.Fatalf("sysinfo device missing from peers: %#v", peers)
	}
	if sysinfoPeer.UserName != server.cfg.Username {
		t.Fatalf("sysinfo peer username = %q, want %q", sysinfoPeer.UserName, server.cfg.Username)
	}
	if sysinfoPeer.DeviceGroupName != "Servers" || sysinfoPeer.Note != "Lab box" {
		t.Fatalf("sysinfo peer metadata = %#v, want group and note", sysinfoPeer)
	}
	if got := stringValue(sysinfoPeer.Info["device_name"]); got != "workstation-01" {
		t.Fatalf("sysinfo peer device_name = %q, want %q", got, "workstation-01")
	}
	if got := stringValue(sysinfoPeer.Info["username"]); got != "alice-pc" {
		t.Fatalf("sysinfo peer username info = %q, want %q", got, "alice-pc")
	}
	if got := stringValue(sysinfoPeer.Info["os"]); got != "Linux / Ubuntu 24.04" {
		t.Fatalf("sysinfo peer os = %q, want %q", got, "Linux / Ubuntu 24.04")
	}

	heartbeatPeer, ok := indexed["222222222"]
	if !ok {
		t.Fatalf("heartbeat-only device missing from peers: %#v", peers)
	}
	if got := stringValue(heartbeatPeer.Info["device_name"]); got != "222222222" {
		t.Fatalf("heartbeat peer device_name = %q, want fallback id", got)
	}
}

func TestLogoutRevokesToken(t *testing.T) {
	t.Parallel()

	server := newTestServer(t)
	handler := server.routes()
	token := loginForToken(t, handler)
	secondToken := loginForToken(t, handler)

	resp := doRequest(t, handler, http.MethodPost, "/api/logout", map[string]any{}, token)
	if resp.Code != http.StatusOK {
		t.Fatalf("logout status = %d, want %d", resp.Code, http.StatusOK)
	}

	resp = doRequest(t, handler, http.MethodPost, "/api/currentUser", map[string]any{}, token)
	if resp.Code != http.StatusUnauthorized {
		t.Fatalf("currentUser after logout status = %d, want %d", resp.Code, http.StatusUnauthorized)
	}
	resp = doRequest(t, handler, http.MethodPost, "/api/currentUser", nil, secondToken)
	if resp.Code != http.StatusOK {
		t.Fatalf("second token after logout status = %d, want %d", resp.Code, http.StatusOK)
	}
}

func TestInventoryDisabledByDefault(t *testing.T) {
	t.Parallel()

	server := newTestServer(t)
	server.cfg.EnableInventory = false
	resp := doRequest(t, server.routes(), http.MethodPost, "/api/heartbeat", map[string]any{"id": "device"}, "")
	if resp.Code != http.StatusNotFound {
		t.Fatalf("disabled heartbeat status = %d, want %d", resp.Code, http.StatusNotFound)
	}
}

func TestAddressBookRevisionConflict(t *testing.T) {
	t.Parallel()

	server := newTestServer(t)
	handler := server.routes()
	token := loginForToken(t, handler)
	resp := doRequest(t, handler, http.MethodGet, "/api/ab", nil, token)
	var current addressBookResponse
	decodeResponse(t, resp, &current)

	resp = doRequest(t, handler, http.MethodPost, "/api/ab", addressBookUpdateRequest{
		Data:     `{"tags":[],"peers":[]}`,
		Revision: &current.Revision,
	}, token)
	if resp.Code != http.StatusOK {
		t.Fatalf("first revision update status = %d, want %d", resp.Code, http.StatusOK)
	}
	stale := current.Revision
	resp = doRequest(t, handler, http.MethodPost, "/api/ab", addressBookUpdateRequest{
		Data:     `{"tags":["stale"],"peers":[]}`,
		Revision: &stale,
	}, token)
	if resp.Code != http.StatusConflict {
		t.Fatalf("stale revision update status = %d, want %d", resp.Code, http.StatusConflict)
	}
}

func TestLoginRateLimit(t *testing.T) {
	t.Parallel()

	server := newTestServer(t)
	server.loginMu.Lock()
	server.loginFailures["192.0.2.1"] = loginFailure{WindowStart: time.Now(), Count: loginMaxFails}
	server.loginMu.Unlock()
	req := httptest.NewRequest(http.MethodPost, "/api/login", bytes.NewBufferString(`{"username":"alice","password":"wrong"}`))
	req.RemoteAddr = "192.0.2.1:1234"
	resp := httptest.NewRecorder()
	server.routes().ServeHTTP(resp, req)
	if resp.Code != http.StatusTooManyRequests {
		t.Fatalf("rate limited login status = %d, want %d", resp.Code, http.StatusTooManyRequests)
	}
}

func TestInvalidAddressBookPayload(t *testing.T) {
	t.Parallel()

	server := newTestServer(t)
	handler := server.routes()
	token := loginForToken(t, handler)

	resp := doRequest(t, handler, http.MethodPost, "/api/ab", addressBookUpdateRequest{Data: "not-json"}, token)
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("invalid /api/ab status = %d, want %d", resp.Code, http.StatusBadRequest)
	}
}

func TestParseCredential(t *testing.T) {
	t.Parallel()

	hash := mustBcryptHash(t, "secret")
	username, parsedHash, err := parseCredential("alice:" + hash)
	if err != nil {
		t.Fatalf("parseCredential failed: %v", err)
	}
	if username != "alice" || parsedHash != hash {
		t.Fatalf("parseCredential returned (%q, %q), want (%q, %q)", username, parsedHash, "alice", hash)
	}
}

func newTestServer(t *testing.T) *apiServer {
	t.Helper()
	cfg := config{
		Listen:          ":0",
		Username:        "alice",
		PasswordHash:    mustBcryptHash(t, "secret"),
		DisplayName:     "Alice",
		DataFile:        filepath.Join(t.TempDir(), "state.json"),
		TokenTTL:        time.Hour,
		EnableInventory: true,
	}
	server, err := newAPIServer(cfg)
	if err != nil {
		t.Fatalf("newAPIServer failed: %v", err)
	}
	return server
}

func mustBcryptHash(t *testing.T, password string) string {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("GenerateFromPassword failed: %v", err)
	}
	return string(hash)
}

func loginForToken(t *testing.T, handler http.Handler) string {
	t.Helper()
	resp := doRequest(t, handler, http.MethodPost, "/api/login", loginRequest{
		Username: "alice",
		Password: "secret",
		Type:     "account",
	}, "")
	if resp.Code != http.StatusOK {
		t.Fatalf("login status = %d, want %d: %s", resp.Code, http.StatusOK, resp.Body.String())
	}
	var body loginResponse
	decodeResponse(t, resp, &body)
	if body.AccessToken == "" {
		t.Fatal("login returned empty token")
	}
	return body.AccessToken
}

func doRequest(t *testing.T, handler http.Handler, method, path string, body any, token string) *httptest.ResponseRecorder {
	t.Helper()
	var payload []byte
	var err error
	if body != nil {
		payload, err = json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal request body failed: %v", err)
		}
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(payload))
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)
	return resp
}

func decodeResponse(t *testing.T, resp *httptest.ResponseRecorder, dst any) {
	t.Helper()
	if err := json.Unmarshal(resp.Body.Bytes(), dst); err != nil {
		t.Fatalf("decode response failed: %v; body=%s", err, resp.Body.String())
	}
}
