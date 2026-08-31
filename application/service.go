// Package application provides the reusable host-facing Audit application
// service. Hosts supply identity and authorization policy; Audit owns event
// construction, persistence orchestration, and host-facing querying.
package application

import (
	"context"
	"strings"
	"time"

	"github.com/domainry/domainry-audit-sdk/contract"
	"github.com/domainry/domainry-foundation/apperror"
	"github.com/domainry/domainry-foundation/secrets"
)

type AppendRequest[P any] struct {
	IdempotencyKey string
	Event          string
	ObjectKey      string
	RecordID       string
	Principal      P
	Summary        string
	Before         map[string]any
	After          map[string]any
	Metadata       map[string]any
}

type Appender[P any] interface {
	AppendAudit(context.Context, AppendRequest[P]) error
}

type TelemetryAppender[P any] interface {
	AppendAuditTelemetry(context.Context, AppendRequest[P])
}

type EventFactory[P any] interface {
	NewAuditEvent(context.Context, AppendRequest[P]) contract.AuditEvent
}

type Reader[S any] interface {
	ListAuditEvents(context.Context, string, contract.AuditEventQuery) ([]contract.AuditEvent, error)
	ListAuditEventsForSystem(context.Context, S, contract.AuditEventQuery) ([]contract.AuditEvent, error)
	ListAuditOptions(context.Context, string, contract.AuditOptionQuery) ([]contract.AuditOption, error)
}

type Store[S any] interface {
	InsertAuditEvent(context.Context, string, contract.AuditEvent) error
	ListAuditEvents(context.Context, string, contract.AuditEventQuery) ([]contract.AuditEvent, error)
	ListAuditEventsForSystem(context.Context, S, contract.AuditEventQuery) ([]contract.AuditEvent, error)
	ListAuditOptions(context.Context, string, contract.AuditOptionQuery) ([]contract.AuditOption, error)
}

type EventWriterStore interface {
	InsertAuditEvent(context.Context, string, contract.AuditEvent) error
}

type EventStore interface {
	EventWriterStore
	ListAuditEvents(context.Context, string, contract.AuditEventQuery) ([]contract.AuditEvent, error)
}

type Policy[P, S any] struct {
	Actor               func(P) contract.Actor
	WorkspaceID         func(P) string
	ValidateCommand     func(P) error
	ValidateQuery       func(P) error
	ValidateSystemQuery func(S) error
	Known               func(P) bool
	CanView             func(P) bool
	ProjectEvents       func(context.Context, []contract.AuditEvent, P) ([]contract.AuditEvent, error)
}

type Service[P, S any] struct {
	store  Store[S]
	policy Policy[P, S]
}

func NewService[P, S any](store Store[S], policy Policy[P, S]) *Service[P, S] {
	return &Service[P, S]{store: store, policy: policy}
}

func (s *Service[P, S]) NewAuditEvent(_ context.Context, request AppendRequest[P]) contract.AuditEvent {
	if s == nil || s.policy.Actor == nil {
		return contract.AuditEvent{}
	}
	event, err := contract.BuildEvent(contract.AppendRequest{
		IdempotencyKey: request.IdempotencyKey, Event: request.Event,
		ObjectKey: request.ObjectKey, RecordID: request.RecordID,
		Actor: s.policy.Actor(request.Principal), Summary: request.Summary,
		Before: request.Before, After: request.After, Metadata: request.Metadata,
	}, time.Now())
	if err != nil {
		return contract.AuditEvent{}
	}
	return event
}

func (s *Service[P, S]) AppendAudit(ctx context.Context, request AppendRequest[P]) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if s == nil || s.store == nil {
		return appError(apperror.KindInternal, "backend.audit.repository_unavailable", nil)
	}
	event := s.NewAuditEvent(ctx, request)
	if err := s.store.InsertAuditEvent(ctx, event.WorkspaceID, event); err != nil {
		return appError(apperror.KindInternal, "backend.internal", err)
	}
	return nil
}

func (s *Service[P, S]) AppendAuditTelemetry(ctx context.Context, request AppendRequest[P]) {
	_ = s.AppendAudit(ctx, request)
}

func (s *Service[P, S]) Append(ctx context.Context, event, objectKey, recordID string, principal P, summary string, before, after map[string]any) {
	s.AppendWithMetadata(ctx, event, objectKey, recordID, principal, summary, before, after, nil)
}

func (s *Service[P, S]) AppendWithMetadata(ctx context.Context, event, objectKey, recordID string, principal P, summary string, before, after, metadata map[string]any) {
	if s == nil || s.policy.ValidateCommand == nil || s.policy.ValidateCommand(principal) != nil {
		return
	}
	s.AppendAuditTelemetry(ctx, AppendRequest[P]{Event: event, ObjectKey: objectKey, RecordID: recordID, Principal: principal, Summary: summary, Before: before, After: after, Metadata: metadata})
}

func (s *Service[P, S]) Events(ctx context.Context, query contract.AuditEventQuery, principal P) ([]contract.AuditEvent, error) {
	if err := s.validateQuery(principal); err != nil {
		return nil, err
	}
	if s.policy.Known == nil || !s.policy.Known(principal) {
		return nil, appError(apperror.KindForbidden, "backend.role.unknown", nil)
	}
	if s.policy.CanView == nil || !s.policy.CanView(principal) {
		return nil, appError(apperror.KindForbidden, "backend.audit.view_permission_required", nil)
	}
	events, err := s.ListAuditEvents(ctx, s.workspaceID(principal), query)
	if err != nil {
		return nil, appError(apperror.KindInternal, "backend.internal", err)
	}
	return s.project(ctx, events, principal)
}

func (s *Service[P, S]) Options(ctx context.Context, query contract.AuditOptionQuery, principal P) ([]contract.AuditOption, error) {
	if err := s.validateQuery(principal); err != nil {
		return nil, err
	}
	if s.policy.Known == nil || !s.policy.Known(principal) {
		return nil, appError(apperror.KindForbidden, "backend.role.unknown", nil)
	}
	if s.policy.CanView == nil || !s.policy.CanView(principal) {
		return nil, appError(apperror.KindForbidden, "backend.audit.view_permission_required", nil)
	}
	switch strings.TrimSpace(query.Field) {
	case "record_id", "actor_id", "role_key", "event":
	default:
		return nil, appError(apperror.KindBadRequest, "backend.audit.option_field_invalid", nil)
	}
	options, err := s.ListAuditOptions(ctx, s.workspaceID(principal), query)
	if err != nil {
		return nil, appError(apperror.KindInternal, "backend.internal", err)
	}
	return options, nil
}

func (s *Service[P, S]) ListAuditEvents(ctx context.Context, workspaceID string, query contract.AuditEventQuery) ([]contract.AuditEvent, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s == nil || s.store == nil {
		return nil, appError(apperror.KindInternal, "backend.audit.repository_unavailable", nil)
	}
	return s.store.ListAuditEvents(ctx, workspaceID, query)
}

func (s *Service[P, S]) ListAuditEventsForSystem(ctx context.Context, scope S, query contract.AuditEventQuery) ([]contract.AuditEvent, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s == nil || s.store == nil {
		return nil, appError(apperror.KindInternal, "backend.audit.repository_unavailable", nil)
	}
	if s.policy.ValidateSystemQuery != nil {
		if err := s.policy.ValidateSystemQuery(scope); err != nil {
			return nil, err
		}
	}
	return s.store.ListAuditEventsForSystem(ctx, scope, query)
}

func (s *Service[P, S]) ListAuditOptions(ctx context.Context, workspaceID string, query contract.AuditOptionQuery) ([]contract.AuditOption, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s == nil || s.store == nil {
		return nil, appError(apperror.KindInternal, "backend.audit.repository_unavailable", nil)
	}
	return s.store.ListAuditOptions(ctx, workspaceID, query)
}

func (s *Service[P, S]) validateQuery(p P) error {
	if s == nil || s.policy.ValidateQuery == nil {
		return appError(apperror.KindForbidden, "backend.workspace_scope_required", nil)
	}
	if err := s.policy.ValidateQuery(p); err != nil {
		return appError(apperror.KindForbidden, "backend.workspace_scope_required", err)
	}
	return nil
}
func (s *Service[P, S]) workspaceID(p P) string {
	if s != nil && s.policy.WorkspaceID != nil {
		if value := strings.TrimSpace(s.policy.WorkspaceID(p)); value != "" {
			return value
		}
	}
	return "default"
}
func (s *Service[P, S]) project(ctx context.Context, events []contract.AuditEvent, p P) ([]contract.AuditEvent, error) {
	if s.policy.ProjectEvents == nil {
		return events, nil
	}
	return s.policy.ProjectEvents(ctx, events, p)
}
func (s *Service[P, S]) SetEventProjector(projector func(context.Context, []contract.AuditEvent, P) ([]contract.AuditEvent, error)) {
	if s != nil {
		s.policy.ProjectEvents = projector
	}
}
func RedactSensitiveMap(value map[string]any) map[string]any { return secrets.RedactMap(value) }
func appError(kind apperror.ErrorKind, code string, err error) error {
	return &apperror.AppError{Kind: kind, Code: code, Err: err}
}
