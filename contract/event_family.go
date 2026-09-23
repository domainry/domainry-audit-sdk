package contract

import (
	"fmt"
	"sort"
	"strings"
)

const (
	EventFamilyAuditExport            = "audit.export"
	EventFamilyBusinessAction         = "runtime.business_action"
	EventFamilyBusinessEntity         = "runtime.business_entity"
	EventFamilyBusinessRecord         = "runtime.business_record"
	EventFamilyIdentityGovernance     = "identity.governance"
	EventFamilyIdentityProfileBinding = "identity.profile_binding"
	EventFamilyIdentitySecurity       = "identity.security"
	EventFamilyLifecycleCompliance    = "lifecycle.compliance"
	EventFamilyRuntimeAgent           = "runtime.agent"
	EventFamilyRuntimeNotification    = "runtime.notification"
	EventFamilyRuntimeOperations      = "runtime.operations"
	EventFamilyRuntimeReport          = "runtime.report"
	EventFamilyRuntimeSecurity        = "runtime.security"
	EventFamilyRuntimeUpload          = "runtime.upload"
	EventFamilyRuntimeWorkflow        = "runtime.workflow"
	EventFamilyRuntimeWorkspace       = "runtime.workspace"
)

// EventFamilyRegistration is the closed contract for one semantic family of
// immutable Audit facts. RequiredMetadata is checked before an event can be
// built or persisted, so an owner cannot replace a typed evidence table with
// unstructured rows that omit the facts its readers depend on.
type EventFamilyRegistration struct {
	Key              string
	Owner            string
	Class            string
	EventPrefixes    []string
	RequiredMetadata []string
}

var eventFamilyRegistrations = map[string]EventFamilyRegistration{
	EventFamilyAuditExport: {
		Key: EventFamilyAuditExport, Owner: "audit", Class: EventClassOperations,
		EventPrefixes: []string{"audit_export_"}, RequiredMetadata: []string{"artifact_id", "result", "reason"},
	},
	EventFamilyBusinessAction: {
		Key: EventFamilyBusinessAction, Owner: "runtime", Class: EventClassBusiness,
		RequiredMetadata: []string{"action_key"},
	},
	EventFamilyBusinessEntity: {
		Key: EventFamilyBusinessEntity, Owner: "runtime", Class: EventClassBusiness,
	},
	EventFamilyBusinessRecord: {
		Key: EventFamilyBusinessRecord, Owner: "runtime", Class: EventClassBusiness,
		EventPrefixes: []string{"record_"},
	},
	EventFamilyIdentityGovernance: {
		Key: EventFamilyIdentityGovernance, Owner: "identity", Class: EventClassGovernance,
	},
	EventFamilyIdentityProfileBinding: {
		Key: EventFamilyIdentityProfileBinding, Owner: "identity", Class: EventClassGovernance,
		EventPrefixes:    []string{"identity.profile_binding."},
		RequiredMetadata: []string{"binding_key", "object_key", "profile_id", "operation", "binding_version", "status"},
	},
	EventFamilyIdentitySecurity: {
		Key: EventFamilyIdentitySecurity, Owner: "identity", Class: EventClassOperations,
	},
	EventFamilyLifecycleCompliance: {
		Key: EventFamilyLifecycleCompliance, Owner: "lifecycle", Class: EventClassGovernance,
		EventPrefixes: []string{"lifecycle."}, RequiredMetadata: []string{"owner"},
	},
	EventFamilyRuntimeAgent: {
		Key: EventFamilyRuntimeAgent, Owner: "agent", Class: EventClassGovernance,
	},
	EventFamilyRuntimeNotification: {
		Key: EventFamilyRuntimeNotification, Owner: "notification", Class: EventClassBusiness,
		RequiredMetadata: []string{"event_type"},
	},
	EventFamilyRuntimeOperations: {
		Key: EventFamilyRuntimeOperations, Owner: "runtime", Class: EventClassOperations,
	},
	EventFamilyRuntimeReport: {
		Key: EventFamilyRuntimeReport, Owner: "report", Class: EventClassGovernance,
		RequiredMetadata: []string{"report_key"},
	},
	EventFamilyRuntimeSecurity: {
		Key: EventFamilyRuntimeSecurity, Owner: "runtime", Class: EventClassOperations,
	},
	EventFamilyRuntimeUpload: {
		Key: EventFamilyRuntimeUpload, Owner: "uploads", Class: EventClassGovernance,
	},
	EventFamilyRuntimeWorkflow: {
		Key: EventFamilyRuntimeWorkflow, Owner: "workflow", Class: EventClassGovernance,
	},
	EventFamilyRuntimeWorkspace: {
		Key: EventFamilyRuntimeWorkspace, Owner: "workspace", Class: EventClassGovernance,
		RequiredMetadata: []string{"action_key"},
	},
}

func EventFamilyRegistrationFor(key string) (EventFamilyRegistration, bool) {
	registration, found := eventFamilyRegistrations[strings.TrimSpace(key)]
	if !found {
		return EventFamilyRegistration{}, false
	}
	return cloneEventFamilyRegistration(registration), true
}

func RegisteredEventFamilies() []EventFamilyRegistration {
	keys := make([]string, 0, len(eventFamilyRegistrations))
	for key := range eventFamilyRegistrations {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]EventFamilyRegistration, 0, len(keys))
	for _, key := range keys {
		result = append(result, cloneEventFamilyRegistration(eventFamilyRegistrations[key]))
	}
	return result
}

func EventFamiliesForClass(class string) []string {
	class = strings.TrimSpace(class)
	result := []string{}
	for _, registration := range RegisteredEventFamilies() {
		if registration.Class == class {
			result = append(result, registration.Key)
		}
	}
	return result
}

func validateEventFamily(family, event string, metadata map[string]any) (EventFamilyRegistration, error) {
	registration, found := EventFamilyRegistrationFor(family)
	if !found {
		return EventFamilyRegistration{}, fmt.Errorf("audit event family %q is not registered", strings.TrimSpace(family))
	}
	event = strings.TrimSpace(event)
	if event == "" {
		return EventFamilyRegistration{}, fmt.Errorf("audit event is required")
	}
	if len(registration.EventPrefixes) > 0 {
		matched := false
		for _, prefix := range registration.EventPrefixes {
			if strings.HasPrefix(event, prefix) {
				matched = true
				break
			}
		}
		if !matched {
			return EventFamilyRegistration{}, fmt.Errorf("audit event %q does not belong to family %q", event, registration.Key)
		}
	}
	for _, key := range registration.RequiredMetadata {
		value, present := metadata[key]
		if !present || value == nil {
			return EventFamilyRegistration{}, fmt.Errorf("audit event family %q requires metadata %q", registration.Key, key)
		}
		if text, ok := value.(string); ok && strings.TrimSpace(text) == "" {
			return EventFamilyRegistration{}, fmt.Errorf("audit event family %q requires non-empty metadata %q", registration.Key, key)
		}
	}
	return registration, nil
}

func ValidatePreparedEvent(event Event) error {
	if strings.TrimSpace(event.WorkspaceID) == "" || strings.TrimSpace(event.ID) == "" || strings.TrimSpace(event.CreatedAt) == "" {
		return fmt.Errorf("prepared audit event is incomplete")
	}
	_, err := validateEventFamily(event.Family, event.Event, event.Metadata)
	return err
}

func cloneEventFamilyRegistration(value EventFamilyRegistration) EventFamilyRegistration {
	value.EventPrefixes = append([]string(nil), value.EventPrefixes...)
	value.RequiredMetadata = append([]string(nil), value.RequiredMetadata...)
	return value
}
