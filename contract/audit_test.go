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

func TestClassifyAuditEventUsesRegisteredFamily(t *testing.T) {
	tests := []struct {
		event AuditEvent
		want  string
	}{
		{AuditEvent{Family: EventFamilyBusinessRecord, Event: "record_updated"}, AuditEventClassBusiness},
		{AuditEvent{Family: EventFamilyIdentityGovernance, Event: "identity_role_updated"}, AuditEventClassGovernance},
		{AuditEvent{Family: EventFamilyIdentitySecurity, Event: "auth_login_failed"}, AuditEventClassOperations},
		{AuditEvent{Family: "unregistered", Event: "anything"}, ""},
	}
	for _, test := range tests {
		if got := ClassifyAuditEvent(test.event); got != test.want {
			t.Fatalf("class=%q want=%q", got, test.want)
		}
	}
	families := RegisteredEventFamilies()
	if len(families) == 0 {
		t.Fatal("event family registry is empty")
	}
	families[0].RequiredMetadata = append(families[0].RequiredMetadata, "changed")
	got, _ := EventFamilyRegistrationFor(families[0].Key)
	if len(got.RequiredMetadata) > 0 && got.RequiredMetadata[len(got.RequiredMetadata)-1] == "changed" {
		t.Fatal("caller mutated event family registry")
	}
}

func TestBuildEventRejectsUnregisteredFamilyAndMissingRequiredMetadata(t *testing.T) {
	now := time.Date(2026, 9, 23, 8, 30, 0, 0, time.UTC)
	base := AppendRequest{Family: EventFamilyAuditExport, Event: "audit_export_prepared", Actor: Actor{WorkspaceID: "workspace-1"}}
	if _, err := BuildEvent(base, now); err == nil {
		t.Fatal("Audit export without required metadata was accepted")
	}
	base.Metadata = map[string]any{"artifact_id": "artifact-1", "result": "success", "reason": "prepared"}
	event, err := BuildEvent(base, now)
	if err != nil || event.Family != EventFamilyAuditExport {
		t.Fatalf("event=%#v err=%v", event, err)
	}
	base.Family = "arbitrary"
	if _, err := BuildEvent(base, now); err == nil {
		t.Fatal("unregistered event family was accepted")
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
		Family:         EventFamilyAuditExport,
		Event:          "audit_export_conflict",
		Actor: Actor{
			WorkspaceID: "workspace-1",
			SubjectID:   "user-1",
			RequestID:   "req-1",
		},
		Metadata: map[string]any{"artifact_id": "artifact-1", "result": "conflict", "reason": "fingerprint_conflict"},
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

func TestBuildEventKeepsExplicitCorrelationIdentities(t *testing.T) {
	now := time.Date(2026, 9, 23, 9, 0, 0, 0, time.UTC)
	event, err := BuildEvent(AppendRequest{
		OperationID: " operation-1 ", OwnerRunID: " workflow-1 ",
		Family: EventFamilyBusinessAction, Event: "action.executed",
		Actor:    Actor{WorkspaceID: "workspace-1", SubjectID: "user-1", CausationID: " cause-1 "},
		Metadata: map[string]any{"action_key": "order.approve"},
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if event.OperationID != "operation-1" || event.CausationID != "cause-1" || event.OwnerRunID != "workflow-1" {
		t.Fatalf("correlation identities=%#v", event)
	}
	if _, duplicated := event.Metadata["causation_id"]; duplicated {
		t.Fatalf("causation identity was duplicated into metadata: %#v", event.Metadata)
	}
}
