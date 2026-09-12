package contract

import (
	"testing"
	"time"
)

func TestCursorRoundTrip(t *testing.T) {
	event := Event{ID: "event-1", CreatedAt: time.Date(2026, 8, 30, 0, 0, 0, 0, time.UTC).Format(time.RFC3339)}
	got, err := DecodeCursor(EncodeCursor(event))
	if err != nil || got.ID != event.ID || got.CreatedAt != event.CreatedAt {
		t.Fatalf("cursor=%+v err=%v", got, err)
	}
}

func TestClassifyAuditEventAndMarkerCopies(t *testing.T) {
	tests := []struct {
		event AuditEvent
		want  string
	}{
		{AuditEvent{Event: "order.updated", ObjectKey: "fulfillment_order"}, AuditEventClassBusiness},
		{AuditEvent{Event: "identity_role_updated", ObjectKey: "role"}, AuditEventClassGovernance},
		{AuditEvent{Event: "identity_recovery_retry", ObjectKey: "role"}, AuditEventClassOperations},
		{AuditEvent{Event: "auth_login_failed", ObjectKey: "identity_login"}, AuditEventClassOperations},
		{AuditEvent{Event: "auth.login_succeeded", ObjectKey: "identity_login"}, AuditEventClassOperations},
		{AuditEvent{Event: "authentication_challenge_failed", ObjectKey: "identity_login"}, AuditEventClassOperations},
		{AuditEvent{Event: "audit_export_conflict", ObjectKey: "audit_events"}, AuditEventClassOperations},
		{AuditEvent{Event: "order_authorized", ObjectKey: "purchase"}, AuditEventClassBusiness},
	}
	for _, test := range tests {
		if got := ClassifyAuditEvent(test.event); got != test.want {
			t.Fatalf("class=%q want=%q", got, test.want)
		}
	}
	markers := AuditEventClassMarkers(AuditEventClassOperations)
	if len(markers) == 0 {
		t.Fatal("operations markers are empty")
	}
	markers[0] = "changed"
	if AuditEventClassMarkers(AuditEventClassOperations)[0] == "changed" {
		t.Fatal("caller mutated marker catalog")
	}
}

func TestAuditEventCursorRejectsInvalidInputs(t *testing.T) {
	for _, invalid := range []string{"", "not-base64", "e30", "eyJ2IjoyLCJjcmVhdGVkX2F0Ijoibm93IiwiaWQiOiJpZCJ9"} {
		if _, err := DecodeAuditEventCursor(invalid); err == nil {
			t.Fatalf("invalid cursor %q accepted", invalid)
		}
	}
}

func TestBuildEventKeepsRequestIDWithIdempotencyKey(t *testing.T) {
	now := time.Date(2026, 9, 12, 8, 30, 0, 0, time.UTC)
	request := AppendRequest{
		IdempotencyKey: "audit-export-conflict:req-1",
		Event:          "audit_export_conflict",
		Actor: Actor{
			WorkspaceID: "workspace-1",
			SubjectID:   "user-1",
			RequestID:   "req-1",
		},
	}

	first, err := BuildEvent(request, now)
	if err != nil {
		t.Fatal(err)
	}
	second, err := BuildEvent(request, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if first.ID != second.ID {
		t.Fatalf("idempotent ids differ: %q != %q", first.ID, second.ID)
	}
	if got := first.Metadata["request_id"]; got != "req-1" {
		t.Fatalf("request_id=%v", got)
	}
}
