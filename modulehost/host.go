package modulehost

import (
	"context"

	sharedartifact "github.com/domainry/domainry-foundation/artifact"
	ormmigration "github.com/domainry/domainry-orm/migration"
	"github.com/domainry/domainry-orm/sqlhost"
)

type Database = sqlhost.Database

type Dialect interface {
	Identifier(string) string
	Table(string) string
	Placeholder(int) string
	Insert(string, []string) string
}

type SchemaMigration = ormmigration.Migration
type SchemaBaseline = ormmigration.Baseline
type SchemaTable = ormmigration.Table
type SchemaColumn = ormmigration.Column
type SchemaIndex = ormmigration.Index

type MigrationRegistrar interface {
	Driver() string
	Schema() string
	ApplyOwnedMigrations(context.Context, string, []SchemaMigration) error
}

type Host interface {
	Database() Database
	Dialect() Dialect
	Migrations() MigrationRegistrar
}

// ArtifactHost enables governed export artifacts. Append/query-only hosts may
// omit it; their Audit binding advertises no export capability.
type ArtifactHost interface {
	ArtifactStore() sharedartifact.ManagedStore
	ArtifactContentStore() sharedartifact.ContentStore
	ArtifactContentWriter() sharedartifact.ContentWriter
}
