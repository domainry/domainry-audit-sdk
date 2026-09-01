// Package auditsdk defines the deployment-neutral Audit module boundary.
package auditsdk

import (
	"context"
	"fmt"
	"strings"

	"github.com/domainry/domainry-audit-sdk/contract"
	"github.com/domainry/domainry-audit-sdk/modulehost"
	"github.com/domainry/domainry-foundation/modulecapability"
)

type DeploymentMode string

const (
	DeploymentModeModule DeploymentMode = "module"
	ProtocolVersionV1                   = "domainry-audit-protocol-v1"
)

type ApplicationRef struct {
	InstallationID string `json:"installation_id"`
}

func (r ApplicationRef) Validate() error {
	if strings.TrimSpace(r.InstallationID) == "" {
		return fmt.Errorf("audit installation identity is required")
	}
	return nil
}

type Capabilities struct {
	TransactionalAppend, Query, Export, SubjectLifecycle, ArchiveReplication, HTTPSurface bool
}
type Descriptor struct {
	ProtocolVersion string
	Mode            DeploymentMode
	Capabilities    Capabilities
}

func (d Descriptor) Validate() error {
	if d.ProtocolVersion != ProtocolVersionV1 || d.Mode != DeploymentModeModule || !d.Capabilities.TransactionalAppend {
		return fmt.Errorf("invalid Audit module descriptor")
	}
	return nil
}

type Factory interface {
	OpenModule(context.Context, ApplicationRef, modulehost.Host) (Binding, error)
}

type Binding interface {
	modulecapability.Binding
	Descriptor() Descriptor
	Factory() contract.EventFactory
	Appender() contract.Appender
	TransactionalAppender() contract.TransactionalAppender
	PreparedAppender() contract.PreparedAppender
	Reader() contract.Reader
	SubjectLifecycle() contract.SubjectLifecycle
	ExportStore() contract.ExportStore
	Exporter() contract.Exporter
	Close(context.Context) error
}

// ApplicationHostBinder completes the product-facing Audit application after
// embedding-host business services are available. Persistence is opened first
// through modulehost.Host; cross-owner record access remains a narrow host capability.
type ApplicationHostBinder interface {
	BindApplicationHost(modulehost.AuditApplicationHost) error
}

type ActorMapper[P any] func(P) contract.Actor
