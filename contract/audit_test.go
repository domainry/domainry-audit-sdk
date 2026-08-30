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
