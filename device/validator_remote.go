/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"bytes"
	"encoding/json"
	"net/http"
	"sync"
	"time"
)

// remoteValidator validates UUIDs against a remote tower API with caching.
// Design mirrors the xray-core fork's validator_remote.go.
type remoteValidator struct {
	endpoint string
	client   *http.Client
	log      *Logger

	cache sync.Map // map[string]*cachedDecision

	inflightMu sync.Mutex
	inflight   map[string]*inflightCall
}

type cachedDecision struct {
	allowed bool

	// If allowed:
	decisionUntil time.Time // long validity window (up to 6h)
	nextTouchAt   time.Time // when to re-touch tower to keep device lock alive

	// If denied:
	denyUntil    time.Time
	errorCode    int
	errorMessage string
}

type inflightCall struct {
	wg     sync.WaitGroup
	result ValidationResult
}

type towerRequest struct {
	UUID string `json:"uuid"`
}

type towerResponse struct {
	Status        int    `json:"status"`
	DecisionTTLSec int   `json:"decisionTtlSec"`
	HeartbeatSec  int    `json:"heartbeatSec"`
	TTLSec        int    `json:"ttlSec"`
	ErrorCode     int    `json:"errorCode"`
	ErrorMessage  string `json:"errorMessage"`
}

func newRemoteValidator(endpoint string, log *Logger) *remoteValidator {
	rv := &remoteValidator{
		endpoint: endpoint,
		client:   &http.Client{Timeout: 5 * time.Second},
		log:      log,
		inflight: make(map[string]*inflightCall),
	}

	// Janitor: clean expired cache entries every 5 minutes
	go rv.janitor()

	return rv
}

// ValidationResult holds the outcome of a UUID validation, including error details for denials.
type ValidationResult struct {
	Allowed      bool
	ErrorCode    int
	ErrorMessage string
}

// Validate checks whether a UUID is allowed to connect.
// Returns a ValidationResult with error details if denied.
func (rv *remoteValidator) Validate(uuid [UUIDBinarySize]byte) ValidationResult {
	key := UUIDToString(uuid)
	now := time.Now()

	// Fast path: cache hit
	if cached, ok := rv.cache.Load(key); ok {
		cd := cached.(*cachedDecision)
		if cd.allowed {
			if now.Before(cd.decisionUntil) {
				// Still valid. Check if we need a background heartbeat.
				if now.After(cd.nextTouchAt) {
					go rv.touchTower(key, cd)
				}
				return ValidationResult{Allowed: true}
			}
			// Expired — fall through to re-validate
		} else {
			if now.Before(cd.denyUntil) {
				return ValidationResult{Allowed: false, ErrorCode: cd.errorCode, ErrorMessage: cd.errorMessage}
			}
			// Expired deny — fall through to re-validate
		}
	}

	// Slow path: call tower (with in-flight deduplication)
	return rv.callTower(key)
}

func (rv *remoteValidator) callTower(key string) ValidationResult {
	rv.inflightMu.Lock()
	if call, ok := rv.inflight[key]; ok {
		rv.inflightMu.Unlock()
		call.wg.Wait()
		return call.result
	}
	call := &inflightCall{}
	call.wg.Add(1)
	rv.inflight[key] = call
	rv.inflightMu.Unlock()

	defer func() {
		call.wg.Done()
		rv.inflightMu.Lock()
		delete(rv.inflight, key)
		rv.inflightMu.Unlock()
	}()

	resp, err := rv.doTowerRequest(key)
	if err != nil {
		rv.log.Errorf("Tower request failed for %s: %v", key, err)
		// Conservative: deny on error, short cache
		call.result = ValidationResult{Allowed: false, ErrorCode: 0, ErrorMessage: "Server temporarily unavailable"}
		rv.cache.Store(key, &cachedDecision{
			allowed:      false,
			denyUntil:    time.Now().Add(10 * time.Second),
			errorCode:    0,
			errorMessage: "Server temporarily unavailable",
		})
		return call.result
	}

	now := time.Now()
	if resp.Status == 0 {
		// Allowed
		call.result = ValidationResult{Allowed: true}
		decisionTTL := clampDuration(time.Duration(resp.DecisionTTLSec)*time.Second, 30*time.Second, 6*time.Hour)
		heartbeat := clampDuration(time.Duration(resp.HeartbeatSec)*time.Second, 5*time.Second, 1*time.Hour)

		rv.cache.Store(key, &cachedDecision{
			allowed:       true,
			decisionUntil: now.Add(decisionTTL),
			nextTouchAt:   now.Add(heartbeat),
		})
		rv.log.Verbosef("Tower: %s ALLOWED (ttl=%v, heartbeat=%v)", key, decisionTTL, heartbeat)
		return call.result
	}

	// Denied
	call.result = ValidationResult{
		Allowed:      false,
		ErrorCode:    resp.ErrorCode,
		ErrorMessage: resp.ErrorMessage,
	}
	denyTTL := clampDuration(time.Duration(resp.TTLSec)*time.Second, 5*time.Second, 5*time.Minute)

	rv.cache.Store(key, &cachedDecision{
		allowed:      false,
		denyUntil:    now.Add(denyTTL),
		errorCode:    resp.ErrorCode,
		errorMessage: resp.ErrorMessage,
	})
	rv.log.Verbosef("Tower: %s DENIED (code=%d, msg=%s, cache=%v)", key, resp.ErrorCode, resp.ErrorMessage, denyTTL)
	return call.result
}

func (rv *remoteValidator) touchTower(key string, cd *cachedDecision) {
	resp, err := rv.doTowerRequest(key)
	if err != nil {
		rv.log.Verbosef("Tower heartbeat failed for %s: %v", key, err)
		return
	}

	now := time.Now()
	if resp.Status == 0 {
		heartbeat := clampDuration(time.Duration(resp.HeartbeatSec)*time.Second, 5*time.Second, 1*time.Hour)
		decisionTTL := clampDuration(time.Duration(resp.DecisionTTLSec)*time.Second, 30*time.Second, 6*time.Hour)
		rv.cache.Store(key, &cachedDecision{
			allowed:       true,
			decisionUntil: now.Add(decisionTTL),
			nextTouchAt:   now.Add(heartbeat),
		})
	} else {
		// Revoked mid-session
		denyTTL := clampDuration(time.Duration(resp.TTLSec)*time.Second, 5*time.Second, 5*time.Minute)
		rv.cache.Store(key, &cachedDecision{
			allowed:   false,
			denyUntil: now.Add(denyTTL),
		})
		rv.log.Verbosef("Tower: %s REVOKED mid-session (code=%d)", key, resp.ErrorCode)
	}
}

func (rv *remoteValidator) doTowerRequest(uuidStr string) (*towerResponse, error) {
	body, _ := json.Marshal(towerRequest{UUID: uuidStr})
	rv.log.Verbosef("Tower HTTP POST %s uuid=%s body=%s", rv.endpoint, uuidStr, string(body))

	req, err := http.NewRequest("POST", rv.endpoint, bytes.NewReader(body))
	if err != nil {
		rv.log.Errorf("Tower HTTP request creation failed: %v", err)
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	start := time.Now()
	resp, err := rv.client.Do(req)
	elapsed := time.Since(start)
	if err != nil {
		rv.log.Errorf("Tower HTTP request failed after %v: %v", elapsed, err)
		return nil, err
	}
	defer resp.Body.Close()

	var tResp towerResponse
	if err := json.NewDecoder(resp.Body).Decode(&tResp); err != nil {
		rv.log.Errorf("Tower HTTP response decode failed (status=%d, elapsed=%v): %v", resp.StatusCode, elapsed, err)
		return nil, err
	}
	rv.log.Verbosef("Tower HTTP response (status=%d, elapsed=%v): status=%d errorCode=%d errorMessage=%q decisionTtl=%d heartbeat=%d ttl=%d",
		resp.StatusCode, elapsed, tResp.Status, tResp.ErrorCode, tResp.ErrorMessage, tResp.DecisionTTLSec, tResp.HeartbeatSec, tResp.TTLSec)
	return &tResp, nil
}

func (rv *remoteValidator) janitor() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		rv.cache.Range(func(key, value any) bool {
			cd := value.(*cachedDecision)
			if cd.allowed && now.After(cd.decisionUntil) {
				rv.cache.Delete(key)
			} else if !cd.allowed && now.After(cd.denyUntil) {
				rv.cache.Delete(key)
			}
			return true
		})
	}
}

func clampDuration(d, min, max time.Duration) time.Duration {
	if d < min {
		return min
	}
	if d > max {
		return max
	}
	return d
}
