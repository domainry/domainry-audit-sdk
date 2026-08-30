// Package application provides the reusable host-facing Audit application
// service. Hosts supply identity and authorization policy; Audit owns event
// construction, persistence orchestration, querying, surfaces, and exports.
package application

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/domainry/domainry-audit-sdk/contract"
	"github.com/domainry/domainry-foundation/apperror"
	"github.com/domainry/domainry-foundation/secrets"
)

const (
	PermissionBusinessAuditRead      = "audit.business.read"
	PermissionBusinessAuditExport    = "audit.business.export"
	PermissionTenantGovernanceRead   = "audit.governance.read"
	PermissionTenantGovernanceExport = "audit.governance.export"
	PermissionOperationsAuditRead    = "audit.ops.read"
	PermissionOperationsAuditExport  = "audit.ops.export"
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
	HasPermission       func(P, string, bool) bool
	ExportPrincipal     func(P) contract.ExportPrincipal
	ProjectEvents       func(context.Context, []contract.AuditEvent, P) ([]contract.AuditEvent, error)
}

type Service[P, S any] struct {
	store    Store[S]
	policy   Policy[P, S]
	exporter contract.Exporter
}

func NewService[P, S any](store Store[S], policy Policy[P, S], exporters ...contract.Exporter) *Service[P, S] {
	service := &Service[P, S]{store: store, policy: policy}
	if len(exporters) > 0 {
		service.exporter = exporters[0]
	}
	return service
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

func (s *Service[P, S]) ConfigureBusinessExport(key []byte, authorizer func(context.Context, contract.ExportFilter, P) error) {
	if s == nil || s.exporter == nil {
		return
	}
	s.exporter.ConfigureExport(key, func(ctx context.Context, filter contract.ExportFilter, actor contract.ExportPrincipal) error {
		principal, ok := actor.AuthorizationContext.(P)
		if !ok {
			return appError(apperror.KindForbidden, "backend.audit.export_scope_changed", nil)
		}
		if authorizer == nil {
			return nil
		}
		return authorizer(ctx, filter, principal)
	})
}

type BusinessAuditExportPrepared = contract.ExportPrepared

func (s *Service[P, S]) PrepareBusinessEventExport(ctx context.Context, request contract.ExportRequest, key string, principal P) (BusinessAuditExportPrepared, error) {
	if err := s.requirePermission(principal, PermissionBusinessAuditExport, false); err != nil {
		return BusinessAuditExportPrepared{}, err
	}
	if err := s.requirePermission(principal, PermissionBusinessAuditRead, false); err != nil {
		return BusinessAuditExportPrepared{}, err
	}
	if s == nil || s.exporter == nil || s.policy.ExportPrincipal == nil {
		return BusinessAuditExportPrepared{}, appError(apperror.KindInternal, "backend.audit.export_unavailable", nil)
	}
	prepared, err := s.exporter.PrepareExport(ctx, request, key, s.policy.ExportPrincipal(principal))
	if err != nil {
		return BusinessAuditExportPrepared{}, exportError(err)
	}
	prepared.ReportSource = "business_audit_events"
	return prepared, nil
}

func (s *Service[P, S]) DownloadBusinessEventExport(ctx context.Context, token string, principal P) ([]byte, string, error) {
	if err := s.requirePermission(principal, PermissionBusinessAuditExport, false); err != nil {
		return nil, "", err
	}
	if err := s.requirePermission(principal, PermissionBusinessAuditRead, false); err != nil {
		return nil, "", err
	}
	if s == nil || s.exporter == nil || s.policy.ExportPrincipal == nil {
		return nil, "", appError(apperror.KindInternal, "backend.audit.export_unavailable", nil)
	}
	content, filename, err := s.exporter.DownloadExport(ctx, token, s.policy.ExportPrincipal(principal))
	if err != nil {
		return nil, "", exportError(err)
	}
	return content, filename, nil
}

type BusinessAuditEventDTO struct {
	ID, Event, ObjectKey, RecordID, ActorID, Summary, CreatedAt string
	Before, After                                               map[string]any
}
type TenantGovernanceAuditEventDTO struct {
	ID, Event, ObjectKey, RecordID, ActorID, RoleKey, Summary, CreatedAt string
	Metadata, Before, After                                              map[string]any
}
type OperationsAuditEventDTO struct {
	ID, Event, ObjectKey, RecordID, ActorID, Summary, CreatedAt string
	Metadata                                                    map[string]any
}
type SurfaceAuditResult[T any] struct {
	Items          []T    `json:"items"`
	Count          int    `json:"count"`
	PageSize       int    `json:"page_size"`
	Truncated      bool   `json:"truncated"`
	NextCursor     string `json:"next_cursor,omitempty"`
	RetentionClass string `json:"retention_class"`
	RetentionDays  int    `json:"retention_days"`
}

func (s *Service[P, S]) BusinessEvents(ctx context.Context, q contract.AuditEventQuery, p P) (SurfaceAuditResult[BusinessAuditEventDTO], error) {
	r, err := s.surface(ctx, contract.SurfaceBusiness, q, p, PermissionBusinessAuditRead, false)
	if err != nil {
		return SurfaceAuditResult[BusinessAuditEventDTO]{}, err
	}
	items := make([]BusinessAuditEventDTO, 0, len(r.Items))
	for _, e := range r.Items {
		items = append(items, BusinessAuditEventDTO{ID: e.ID, Event: e.Event, ObjectKey: e.ObjectKey, RecordID: e.RecordID, ActorID: e.ActorID, Summary: e.Summary, Before: e.Before, After: e.After, CreatedAt: e.CreatedAt})
	}
	return surfaceResult(r, items), nil
}

func (s *Service[P, S]) TenantGovernanceEvents(ctx context.Context, q contract.AuditEventQuery, p P) (SurfaceAuditResult[TenantGovernanceAuditEventDTO], error) {
	r, err := s.surface(ctx, contract.SurfaceGovernance, q, p, PermissionTenantGovernanceRead, true)
	if err != nil {
		return SurfaceAuditResult[TenantGovernanceAuditEventDTO]{}, err
	}
	items := make([]TenantGovernanceAuditEventDTO, 0, len(r.Items))
	for _, e := range r.Items {
		items = append(items, TenantGovernanceAuditEventDTO{ID: e.ID, Event: e.Event, ObjectKey: e.ObjectKey, RecordID: e.RecordID, ActorID: e.ActorID, RoleKey: e.RoleKey, Summary: e.Summary, Metadata: e.Metadata, Before: e.Before, After: e.After, CreatedAt: e.CreatedAt})
	}
	return surfaceResult(r, items), nil
}

func (s *Service[P, S]) OperationsEvents(ctx context.Context, q contract.AuditEventQuery, p P) (SurfaceAuditResult[OperationsAuditEventDTO], error) {
	r, err := s.surface(ctx, contract.SurfaceOperations, q, p, PermissionOperationsAuditRead, false)
	if err != nil {
		return SurfaceAuditResult[OperationsAuditEventDTO]{}, err
	}
	items := make([]OperationsAuditEventDTO, 0, len(r.Items))
	for _, e := range r.Items {
		items = append(items, OperationsAuditEventDTO{ID: e.ID, Event: e.Event, ObjectKey: e.ObjectKey, RecordID: e.RecordID, ActorID: e.ActorID, Summary: e.Summary, Metadata: e.Metadata, CreatedAt: e.CreatedAt})
	}
	return surfaceResult(r, items), nil
}

func (s *Service[P, S]) TenantGovernanceExport(ctx context.Context, q contract.AuditEventQuery, p P) (SurfaceAuditResult[TenantGovernanceAuditEventDTO], error) {
	if err := s.requirePermission(p, PermissionTenantGovernanceExport, true); err != nil {
		return SurfaceAuditResult[TenantGovernanceAuditEventDTO]{}, err
	}
	return s.TenantGovernanceEvents(ctx, q, p)
}

func (s *Service[P, S]) OperationsExport(ctx context.Context, q contract.AuditEventQuery, p P) (SurfaceAuditResult[OperationsAuditEventDTO], error) {
	if err := s.requirePermission(p, PermissionOperationsAuditExport, false); err != nil {
		return SurfaceAuditResult[OperationsAuditEventDTO]{}, err
	}
	return s.OperationsEvents(ctx, q, p)
}

func (s *Service[P, S]) surface(ctx context.Context, kind contract.SurfaceKind, q contract.AuditEventQuery, p P, permission string, inherited bool) (contract.SurfaceResult, error) {
	if err := s.requirePermission(p, permission, inherited); err != nil {
		return contract.SurfaceResult{}, err
	}
	if err := s.validateQuery(p); err != nil {
		return contract.SurfaceResult{}, err
	}
	actor := s.policy.Actor(p)
	plan, err := contract.PlanSurface(kind, q, actor.SubjectID, time.Now())
	if err != nil {
		return contract.SurfaceResult{}, appError(apperror.KindBadRequest, "backend.audit.cursor_invalid", err)
	}
	events, err := s.ListAuditEvents(ctx, s.workspaceID(p), plan.Query)
	if err != nil {
		return contract.SurfaceResult{}, err
	}
	events, err = s.project(ctx, events, p)
	if err != nil {
		return contract.SurfaceResult{}, err
	}
	return contract.ProjectSurface(events, plan), nil
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
func (s *Service[P, S]) requirePermission(p P, permission string, inherited bool) error {
	if s == nil || s.policy.Known == nil || !s.policy.Known(p) || s.policy.HasPermission == nil || !s.policy.HasPermission(p, permission, inherited) {
		return appError(apperror.KindForbidden, "backend.audit.view_permission_required", nil)
	}
	return nil
}
func surfaceResult[T any](r contract.SurfaceResult, items []T) SurfaceAuditResult[T] {
	return SurfaceAuditResult[T]{Items: items, Count: len(items), PageSize: r.PageSize, Truncated: r.Truncated, NextCursor: r.NextCursor, RetentionClass: r.RetentionClass, RetentionDays: r.RetentionDays}
}
func RedactSensitiveMap(value map[string]any) map[string]any { return secrets.RedactMap(value) }
func appError(kind apperror.ErrorKind, code string, err error) error {
	return &apperror.AppError{Kind: kind, Code: code, Err: err}
}
func exportError(err error) error {
	var exported *contract.ExportError
	if !errors.As(err, &exported) {
		return err
	}
	kind, code := apperror.KindBadRequest, "backend.audit."+exported.Code
	switch exported.Code {
	case "export_unavailable", "export_encode_failed", "export_persistence_failed", "export_audit_failed":
		kind = apperror.KindInternal
	case "idempotency_key_conflict":
		kind, code = apperror.KindConflict, "backend.idempotency.key_conflict"
	case "idempotency_key_required":
		code = "backend.idempotency.key_required"
	case "export_download_not_found":
		kind = apperror.KindNotFound
	case "export_requester_mismatch", "export_download_expired", "export_scope_changed", "export_integrity_failed", "export_actor_scope_denied", "export_role_scope_denied":
		kind = apperror.KindForbidden
	}
	return appError(kind, code, err)
}
