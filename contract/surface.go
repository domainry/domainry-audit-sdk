package contract

import (
	"fmt"
	"strings"
	"time"

	"github.com/domainry/domainry-foundation/secrets"
)

type SurfaceKind string

const (
	SurfaceBusiness   SurfaceKind = "business"
	SurfaceGovernance SurfaceKind = "governance"
	SurfaceOperations SurfaceKind = "operations"
)
const (
	BusinessRetentionDays   = 365
	GovernanceRetentionDays = 2555
	OperationsRetentionDays = 90
	BusinessMaxPageSize     = 200
)

type SurfacePlan struct {
	Kind           SurfaceKind
	Query          AuditEventQuery
	PageSize       int
	RetentionClass string
	RetentionDays  int
}
type SurfaceEvent struct {
	ID, Event, ObjectKey, RecordID, ActorID, RoleKey, Summary, CreatedAt string
	Metadata, Before, After                                              map[string]any
}
type SurfaceResult struct {
	Items                      []SurfaceEvent
	Count, PageSize            int
	Truncated                  bool
	NextCursor, RetentionClass string
	RetentionDays              int
}

func PlanSurface(kind SurfaceKind, query AuditEventQuery, actorID string, now time.Time) (SurfacePlan, error) {
	days := 0
	class := ""
	switch kind {
	case SurfaceBusiness:
		days = BusinessRetentionDays
		class = "business_history"
		if strings.TrimSpace(query.ObjectKey) == "" || strings.TrimSpace(query.RecordID) == "" {
			query.ActorID = actorID
		}
		if query.Limit > BusinessMaxPageSize {
			query.Limit = BusinessMaxPageSize
		}
		if query.Cursor != "" {
			if _, err := DecodeAuditEventCursor(query.Cursor); err != nil {
				return SurfacePlan{}, fmt.Errorf("audit cursor invalid: %w", err)
			}
		}
	case SurfaceGovernance:
		days = GovernanceRetentionDays
		class = "tenant_governance"
	case SurfaceOperations:
		days = OperationsRetentionDays
		class = "technical_security"
	default:
		return SurfacePlan{}, fmt.Errorf("unsupported audit surface %q", kind)
	}
	cutoff := now.UTC().AddDate(0, 0, -days)
	if current, err := time.Parse(time.RFC3339, strings.TrimSpace(query.CreatedFrom)); err != nil || current.Before(cutoff) {
		query.CreatedFrom = cutoff.Format(time.RFC3339)
	}
	if query.Limit <= 0 || query.Limit > 1000 {
		query.Limit = 200
	}
	pageSize := query.Limit
	if kind == SurfaceBusiness {
		query.Limit = pageSize + 1
	}
	query.Class = string(kind)
	return SurfacePlan{Kind: kind, Query: query, PageSize: pageSize, RetentionClass: class, RetentionDays: days}, nil
}

func ProjectSurface(events []AuditEvent, plan SurfacePlan) SurfaceResult {
	truncated := plan.Kind == SurfaceBusiness && len(events) > plan.PageSize
	if truncated {
		events = events[:plan.PageSize]
	}
	next := ""
	if truncated && len(events) > 0 {
		next = EncodeAuditEventCursor(events[len(events)-1])
	}
	items := make([]SurfaceEvent, 0, len(events))
	for _, e := range events {
		if ClassifyAuditEvent(e) != string(plan.Kind) {
			continue
		}
		item := SurfaceEvent{ID: e.ID, Event: e.Event, ObjectKey: e.ObjectKey, RecordID: e.RecordID, ActorID: e.ActorID, RoleKey: e.RoleKey, Summary: e.Summary, CreatedAt: e.CreatedAt}
		switch plan.Kind {
		case SurfaceBusiness:
			item.Before = secrets.RedactMap(e.Before)
			item.After = secrets.RedactMap(e.After)
		case SurfaceGovernance:
			item.Metadata = secrets.RedactMap(e.Metadata)
			item.Before = secrets.RedactMap(e.Before)
			item.After = secrets.RedactMap(e.After)
		case SurfaceOperations:
			item.Metadata = secrets.RedactMap(e.Metadata)
		}
		items = append(items, item)
	}
	return SurfaceResult{Items: items, Count: len(items), PageSize: plan.PageSize, Truncated: truncated, NextCursor: next, RetentionClass: plan.RetentionClass, RetentionDays: plan.RetentionDays}
}
