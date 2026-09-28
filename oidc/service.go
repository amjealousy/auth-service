package oidc

import (
	"sync"
	"time"
)

type OIDCService struct {
	provider *OIDCProvider
	mu       sync.Mutex
	flows    map[string]authorizationRequest
	codes    map[string]AuthCodeData
}

func NewOIDCService(provider *OIDCProvider) *OIDCService {
	return &OIDCService{
		provider: provider,
		flows:    make(map[string]authorizationRequest),
		codes:    make(map[string]AuthCodeData),
	}
}

type authorizationRequest struct {
	FlowID        string
	ClientID      string
	RedirectURI   string
	State         string
	Nonce         string
	Scope         string
	CodeChallenge string
	ExpiresAt     time.Time
}

type AuthCodeData struct {
	FlowID        string
	UserID        string
	Username      string
	ClientID      string
	RedirectURI   string
	Nonce         string
	Scope         string
	CodeChallenge string
	ExpiresAt     time.Time
}

func (s *OIDCService) putFlow(request authorizationRequest) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.removeExpiredLocked(time.Now())
	s.flows[request.FlowID] = request
}

func (s *OIDCService) getFlow(flowID string) (authorizationRequest, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	request, ok := s.flows[flowID]
	if !ok || time.Now().After(request.ExpiresAt) {
		delete(s.flows, flowID)
		return authorizationRequest{}, false
	}
	return request, true
}

func (s *OIDCService) consumeFlow(flowID string) (authorizationRequest, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	request, ok := s.flows[flowID]
	delete(s.flows, flowID)
	if !ok || time.Now().After(request.ExpiresAt) {
		return authorizationRequest{}, false
	}
	return request, true
}

func (s *OIDCService) putCode(code string, data AuthCodeData) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.removeExpiredLocked(time.Now())
	s.codes[code] = data
}

func (s *OIDCService) consumeCode(code, clientID, redirectURI, verifier string) (AuthCodeData, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, ok := s.codes[code]
	if !ok {
		return AuthCodeData{}, "code_not_found"
	}
	if time.Now().After(data.ExpiresAt) {
		delete(s.codes, code)
		return data, "code_expired"
	}
	if data.ClientID != clientID {
		return data, "client_mismatch"
	}
	if data.RedirectURI != redirectURI {
		return data, "redirect_mismatch"
	}
	if !validPKCE(data.CodeChallenge, verifier) {
		return data, "pkce_failed"
	}
	delete(s.codes, code)
	return data, "accepted"
}

func (s *OIDCService) removeExpiredLocked(now time.Time) {
	for id, request := range s.flows {
		if now.After(request.ExpiresAt) {
			delete(s.flows, id)
		}
	}
	for code, data := range s.codes {
		if now.After(data.ExpiresAt) {
			delete(s.codes, code)
		}
	}
}
