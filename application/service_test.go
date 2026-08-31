package application

import (
	"context"
	"testing"

	"github.com/domainry/domainry-audit-sdk/contract"
)

type testPrincipal struct {
	known, view bool
	workspace   string
	user        string
}
type testScope struct{ valid bool }
type memoryStore struct {
	events  []contract.AuditEvent
	options []contract.AuditOption
}

func (s *memoryStore) InsertAuditEvent(_ context.Context, workspace string, event contract.AuditEvent) error {
	if workspace != event.WorkspaceID {
		return context.Canceled
	}
	s.events = append(s.events, event)
	return nil
}
func (s *memoryStore) ListAuditEvents(context.Context, string, contract.AuditEventQuery) ([]contract.AuditEvent, error) {
	return append([]contract.AuditEvent(nil), s.events...), nil
}
func (s *memoryStore) ListAuditEventsForSystem(context.Context, testScope, contract.AuditEventQuery) ([]contract.AuditEvent, error) {
	return append([]contract.AuditEvent(nil), s.events...), nil
}
func (s *memoryStore) ListAuditOptions(context.Context, string, contract.AuditOptionQuery) ([]contract.AuditOption, error) {
	return append([]contract.AuditOption(nil), s.options...), nil
}

func testPolicy() Policy[testPrincipal, testScope] {
	return Policy[testPrincipal, testScope]{
		Actor: func(p testPrincipal) contract.Actor {
			return contract.Actor{WorkspaceID: p.workspace, SubjectID: p.user, Kind: "user"}
		},
		WorkspaceID:     func(p testPrincipal) string { return p.workspace },
		ValidateCommand: func(testPrincipal) error { return nil },
		ValidateQuery:   func(testPrincipal) error { return nil },
		ValidateSystemQuery: func(s testScope) error {
			if !s.valid {
				return context.Canceled
			}
			return nil
		},
		Known:   func(p testPrincipal) bool { return p.known },
		CanView: func(p testPrincipal) bool { return p.view },
	}
}

func TestServiceOwnsReusableAuditApplicationFlow(t *testing.T) {
	store := &memoryStore{options: []contract.AuditOption{{Value: "created", Label: "created"}}}
	service := NewService(store, testPolicy())
	principal := testPrincipal{known: true, view: true, workspace: "workspace-1", user: "user-1"}
	service.AppendWithMetadata(t.Context(), "created", "order", "order-1", principal, "created", nil, map[string]any{"password": "secret"}, map[string]any{"token": "secret"})
	if len(store.events) != 1 || store.events[0].WorkspaceID != "workspace-1" || store.events[0].ActorID != "user-1" {
		t.Fatalf("events=%#v", store.events)
	}
	if store.events[0].After["password"] != "[REDACTED]" || store.events[0].Metadata["token"] != "[REDACTED]" {
		t.Fatalf("event was not redacted: %#v", store.events[0])
	}
	events, err := service.Events(t.Context(), contract.AuditEventQuery{}, principal)
	if err != nil || len(events) != 1 {
		t.Fatalf("events=%#v err=%v", events, err)
	}
	options, err := service.Options(t.Context(), contract.AuditOptionQuery{Field: "event"}, principal)
	if err != nil || len(options) != 1 {
		t.Fatalf("options=%#v err=%v", options, err)
	}
}

func TestServiceRejectsUnknownAndInvalidOptionQueries(t *testing.T) {
	service := NewService(&memoryStore{}, testPolicy())
	if _, err := service.Events(t.Context(), contract.AuditEventQuery{}, testPrincipal{}); err == nil {
		t.Fatal("unknown principal was accepted")
	}
	principal := testPrincipal{known: true, view: true, workspace: "workspace-1"}
	if _, err := service.Options(t.Context(), contract.AuditOptionQuery{Field: "password"}, principal); err == nil {
		t.Fatal("invalid option field was accepted")
	}
	if _, err := service.ListAuditEventsForSystem(t.Context(), testScope{}, contract.AuditEventQuery{}); err == nil {
		t.Fatal("invalid system scope was accepted")
	}
}
