package contract

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/domainry/domainry-foundation/secrets"
)

var ErrExportIdempotencyConflict = errors.New("audit export idempotency key reused with different filters or authorization scope")

type ExportFilter struct {
	Event       string `json:"event,omitempty"`
	ObjectKey   string `json:"object_key,omitempty"`
	RecordID    string `json:"record_id,omitempty"`
	ActorID     string `json:"actor_id,omitempty"`
	RoleKey     string `json:"role_key,omitempty"`
	Result      string `json:"result,omitempty"`
	CreatedFrom string `json:"created_from,omitempty"`
	CreatedTo   string `json:"created_to,omitempty"`
}
type ExportRequest struct {
	Filters ExportFilter `json:"filters"`
	Format  string       `json:"format,omitempty"`
}
type ExportArtifact struct {
	ID                       string       `json:"id"`
	WorkspaceID              string       `json:"workspace_id"`
	RequesterUserID          string       `json:"requester_user_id"`
	RoleKey                  string       `json:"role_key"`
	IdempotencyKey           string       `json:"idempotency_key"`
	Filters                  ExportFilter `json:"filters"`
	ScopeSHA256              string       `json:"scope_sha256"`
	AuthorizationScopeSHA256 string       `json:"authorization_scope_sha256"`
	TokenSHA256              string       `json:"token_sha256"`
	Filename                 string       `json:"filename"`
	ContentSHA256            string       `json:"content_sha256"`
	RowCount                 int          `json:"row_count"`
	Content                  []byte       `json:"-"`
	AuditIdentity            string       `json:"audit_identity"`
	Status                   string       `json:"status"`
	CreatedAt                string       `json:"created_at"`
	ExpiresAt                string       `json:"expires_at"`
	DownloadCount            int          `json:"download_count"`
	LastDownloadedAt         string       `json:"last_downloaded_at,omitempty"`
}

type ExportStore interface {
	CreateOrGetExport(context.Context, ExportArtifact) (ExportArtifact, bool, error)
	ExportByTokenHash(context.Context, string, string) (ExportArtifact, bool, error)
	RecordExportDownload(context.Context, string, string, string) (bool, error)
}

type ExportPrincipal struct {
	WorkspaceID, UserID, RoleKey, AuthorizationRevision, SystemScope string
	RequestID, CorrelationID                                         string
	SystemCapabilities                                               []string
	AuthorizationContext                                             any `json:"-"`
}
type ExportPrepared struct {
	ID            string       `json:"id"`
	ReportSource  string       `json:"report_source"`
	Filename      string       `json:"filename"`
	ContentSHA256 string       `json:"content_sha256"`
	RowCount      int          `json:"row_count"`
	AuditIdentity string       `json:"audit_identity"`
	ScopeSHA256   string       `json:"scope_sha256"`
	Filters       ExportFilter `json:"filters"`
	DownloadToken string       `json:"download_token"`
	ExpiresAt     string       `json:"expires_at"`
}
type ExportAuthorizer func(context.Context, ExportFilter, ExportPrincipal) error
type ExportError struct {
	Code string
	Err  error
}

func (e *ExportError) Error() string {
	if e == nil {
		return ""
	}
	if e.Err != nil {
		return e.Code + ": " + e.Err.Error()
	}
	return e.Code
}
func (e *ExportError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

type Exporter interface {
	ConfigureExport([]byte, ExportAuthorizer)
	PrepareExport(context.Context, ExportRequest, string, ExportPrincipal) (ExportPrepared, error)
	DownloadExport(context.Context, string, ExportPrincipal) ([]byte, string, error)
}

const (
	EventClassBusiness   = "business"
	EventClassGovernance = "governance"
	EventClassOperations = "operations"
)

var operationsClassMarkers = []string{"break_glass", "support_session", "security", "recovery", "retry", "dead_letter", "lease", "fencing", "worker", "infrastructure", "runtime_operation", "scheduler_run", "integration_event", "integration_outbox", "workflow_execution", "cleanup_job"}
var governanceClassMarkers = []string{"identity", "role", "permission", "menu", "metadata", "definition", "change_plan", "policy", "connection", "secret", "configuration", "notification_template", "localized_text", "api_key"}

func EventClassMarkers(class string) []string {
	switch strings.TrimSpace(class) {
	case EventClassOperations:
		return append([]string(nil), operationsClassMarkers...)
	case EventClassGovernance:
		return append([]string(nil), governanceClassMarkers...)
	default:
		return nil
	}
}

type Actor struct {
	WorkspaceID           string `json:"workspace_id"`
	SubjectID             string `json:"subject_id"`
	RoleKey               string `json:"role_key,omitempty"`
	Kind                  string `json:"kind,omitempty"`
	RequestID             string `json:"request_id,omitempty"`
	CorrelationID         string `json:"correlation_id,omitempty"`
	AuthorizationRevision string `json:"authorization_revision,omitempty"`
}

type AppendRequest struct {
	IdempotencyKey string         `json:"idempotency_key,omitempty"`
	Event          string         `json:"event"`
	ObjectKey      string         `json:"object_key,omitempty"`
	RecordID       string         `json:"record_id,omitempty"`
	Actor          Actor          `json:"actor"`
	Summary        string         `json:"summary"`
	Before         map[string]any `json:"before,omitempty"`
	After          map[string]any `json:"after,omitempty"`
	Metadata       map[string]any `json:"metadata,omitempty"`
}

func BuildEvent(request AppendRequest, now time.Time) (AuditEvent, error) {
	request.Event = strings.TrimSpace(request.Event)
	request.Actor.WorkspaceID = strings.TrimSpace(request.Actor.WorkspaceID)
	if request.Event == "" || request.Actor.WorkspaceID == "" {
		return AuditEvent{}, fmt.Errorf("audit event and workspace are required")
	}
	if strings.TrimSpace(request.Actor.SubjectID) == "" {
		request.Actor.SubjectID = "system"
	}
	metadata := secrets.RedactMap(request.Metadata)
	if metadata == nil {
		metadata = map[string]any{}
	}
	metadata["workspace_id"] = request.Actor.WorkspaceID
	if request.Actor.RequestID != "" {
		metadata["request_id"] = request.Actor.RequestID
	}
	if request.Actor.CorrelationID != "" {
		metadata["correlation_id"] = request.Actor.CorrelationID
	}
	if request.Actor.SubjectID != "" {
		metadata["actor_id"] = request.Actor.SubjectID
	}
	if request.Actor.RoleKey != "" {
		metadata["role_key"] = request.Actor.RoleKey
	}
	now = now.UTC()
	id := NewEventID(now)
	if strings.TrimSpace(request.IdempotencyKey) != "" {
		id = IdempotentEventID(request.Actor.WorkspaceID, request.IdempotencyKey)
	}
	return AuditEvent{ID: id, WorkspaceID: request.Actor.WorkspaceID, Event: request.Event, ObjectKey: request.ObjectKey, RecordID: request.RecordID, ActorID: request.Actor.SubjectID, RoleKey: request.Actor.RoleKey, Summary: strings.TrimSpace(request.Summary), Metadata: metadata, Before: secrets.RedactMap(request.Before), After: secrets.RedactMap(request.After), CreatedAt: now.Format(time.RFC3339)}, nil
}

// Event preserves the installed Runtime/Identity storage and JSON contract so
// the module can take ownership without a data migration.
type AuditEvent struct {
	ID          string         `json:"id"`
	WorkspaceID string         `json:"workspace_id"`
	Event       string         `json:"event"`
	ObjectKey   string         `json:"object_key,omitempty"`
	RecordID    string         `json:"record_id,omitempty"`
	ActorID     string         `json:"actor_id"`
	RoleKey     string         `json:"role_key"`
	Summary     string         `json:"summary"`
	Metadata    map[string]any `json:"metadata,omitempty"`
	Before      map[string]any `json:"before,omitempty"`
	After       map[string]any `json:"after,omitempty"`
	CreatedAt   string         `json:"created_at"`
}
type Event = AuditEvent

func ClassifyEvent(event Event) string {
	eventKey := strings.ToLower(strings.TrimSpace(event.Event))
	if eventKey == "auth" || strings.HasPrefix(eventKey, "auth_") || strings.HasPrefix(eventKey, "auth.") || strings.HasPrefix(eventKey, "authentication_") || strings.HasPrefix(eventKey, "authentication.") {
		return EventClassOperations
	}
	if eventKey == "audit_export_conflict" {
		return EventClassOperations
	}
	value := eventKey + " " + strings.ToLower(event.ObjectKey)
	for _, marker := range operationsClassMarkers {
		if strings.Contains(value, marker) {
			return EventClassOperations
		}
	}
	for _, marker := range governanceClassMarkers {
		if strings.Contains(value, marker) {
			return EventClassGovernance
		}
	}
	return EventClassBusiness
}

type AuditEventQuery struct {
	ObjectKey, RecordID, Event, Class, ActorID, RoleKey, RequestID, CreatedFrom, CreatedTo string
	Limit                                                                                  int
	Cursor                                                                                 string
}
type Query = AuditEventQuery
type AuditEventCursor struct {
	CreatedAt string
	ID        string
}
type Cursor = AuditEventCursor

func EncodeCursor(event Event) string {
	raw, _ := json.Marshal(struct {
		Version   int    `json:"v"`
		CreatedAt string `json:"created_at"`
		ID        string `json:"id"`
	}{1, strings.TrimSpace(event.CreatedAt), strings.TrimSpace(event.ID)})
	return base64.RawURLEncoding.EncodeToString(raw)
}
func DecodeCursor(value string) (Cursor, error) {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 2048 {
		return Cursor{}, errors.New("audit event cursor is empty or too large")
	}
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return Cursor{}, errors.New("audit event cursor is not base64url")
	}
	var payload struct {
		Version   int    `json:"v"`
		CreatedAt string `json:"created_at"`
		ID        string `json:"id"`
	}
	if json.Unmarshal(raw, &payload) != nil || payload.Version != 1 || strings.TrimSpace(payload.CreatedAt) == "" || strings.TrimSpace(payload.ID) == "" {
		return Cursor{}, errors.New("audit event cursor payload is invalid")
	}
	return Cursor{CreatedAt: strings.TrimSpace(payload.CreatedAt), ID: strings.TrimSpace(payload.ID)}, nil
}

type AuditOption struct {
	Value string `json:"value"`
	Label string `json:"label"`
	Count int    `json:"count"`
}
type Option = AuditOption
type AuditOptionQuery struct {
	Field, Query, ObjectKey, CreatedFrom, CreatedTo string
	Limit                                           int
}
type OptionQuery = AuditOptionQuery

var eventSequence atomic.Uint64

func NewEventID(now time.Time) string {
	return fmt.Sprintf("audit_%d_%d", now.UnixNano(), eventSequence.Add(1))
}
func IdempotentEventID(workspaceID, key string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(workspaceID) + "\x00" + strings.TrimSpace(key)))
	return "audit_idem_" + hex.EncodeToString(sum[:16])
}

const (
	AuditEventClassBusiness   = EventClassBusiness
	AuditEventClassGovernance = EventClassGovernance
	AuditEventClassOperations = EventClassOperations
)

func AuditEventClassMarkers(class string) []string                  { return EventClassMarkers(class) }
func ClassifyAuditEvent(event AuditEvent) string                    { return ClassifyEvent(event) }
func EncodeAuditEventCursor(event AuditEvent) string                { return EncodeCursor(event) }
func DecodeAuditEventCursor(value string) (AuditEventCursor, error) { return DecodeCursor(value) }

type EventFactory interface {
	Build(context.Context, AppendRequest) (Event, error)
}
type Appender interface {
	Append(context.Context, AppendRequest) (Event, error)
}
type TelemetryAppender interface {
	AppendTelemetry(context.Context, AppendRequest)
}
type Reader interface {
	List(context.Context, string, Query) ([]Event, error)
	ListSystem(context.Context, Query) ([]Event, error)
	Options(context.Context, string, OptionQuery) ([]Option, error)
}
type SubjectLifecycle interface {
	PreviewSubject(context.Context, string, string) (json.RawMessage, error)
	ExportSubject(context.Context, string, string) (json.RawMessage, error)
	EraseSubject(context.Context, string, string) (json.RawMessage, error)
}
type Result interface{ RowsAffected() (int64, error) }
type Row interface{ Scan(...any) error }
type Transaction interface {
	ExecContext(context.Context, string, ...any) (Result, error)
	QueryRowContext(context.Context, string, ...any) Row
}
type TransactionalAppender interface {
	AppendWithin(context.Context, Transaction, AppendRequest) (Event, error)
}
type PreparedAppender interface {
	AppendPrepared(context.Context, Event) error
	AppendPreparedWithin(context.Context, Transaction, Event) error
}
