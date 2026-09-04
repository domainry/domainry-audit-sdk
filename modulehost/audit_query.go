package modulehost

import (
	"context"

	"github.com/domainry/domainry-audit-sdk/contract"
	identitysdk "github.com/domainry/domainry-identity-sdk"
)

// AuditPrincipalRequest contains authenticated identity facts plus the
// host-owned business-profile selection needed by Audit product surfaces.
type AuditPrincipalRequest struct {
	Identity           identitysdk.Principal
	BusinessProfileKey string
	BusinessProfileID  string
	RequestID          string
	CorrelationID      string
}

// AuditPrincipal is the host-resolved authority used by Audit. The base
// Identity principal remains intact while AuthorizationRevision also covers
// host-owned business-profile facts.
type AuditPrincipal struct {
	Identity              identitysdk.Principal
	BusinessProfileKey    string
	BusinessProfileID     string
	RequestID             string
	CorrelationID         string
	AuthorizationRevision string
}

// AuditApplicationHost is the minimal cross-owner seam required by Audit HTTP
// use cases. Audit owns query/export policy; the embedding host owns record
// authorization, business-profile resolution, and record-field projection.
type AuditApplicationHost interface {
	ResolveAuditPrincipal(context.Context, AuditPrincipalRequest) (AuditPrincipal, error)
	AuthorizeAuditRecord(context.Context, AuditPrincipal, string, string) error
	ProjectAuditEvents(context.Context, AuditPrincipal, []contract.Event) ([]contract.Event, error)
	AuditExportTokenKey() []byte
}
