// Package audit classifies Talos MachineService gRPC methods so the proxy
// knows which calls to record and which to forward silently.
//
// The method names below are the wire-level gRPC full-method paths taken
// verbatim from siderolabs/talos/pkg/machinery v1.14.0
// (api/machine/machine_grpc.pb.go). The proxy forwards every method
// transparently regardless of class; the class only decides what, if
// anything, is written to the audit trail.
package audit

// Class is how a MachineService method is treated by the audit trail.
type Class int

const (
	// ClassUnclassified is any method not present in the table. It is the
	// zero value on purpose: a method the proxy does not recognise is audited
	// (metadata only) rather than dropped, so a method added by a newer Talos
	// version cannot slip through unrecorded. A rising count of unclassified
	// calls is the signal to extend the table.
	ClassUnclassified Class = iota

	// ClassMutating changes node, cluster, or configuration state. These are
	// the "who changed what" calls; ApplyConfiguration carries the full
	// machine config in its request body.
	ClassMutating

	// ClassSensitive does not mutate state but issues credentials or egresses
	// data (kubeconfig, a freshly signed client cert, a file copy, an etcd
	// snapshot, a packet capture). Audited as metadata only; the body is
	// deliberately not recorded because it carries secrets.
	ClassSensitive

	// ClassReadOnly is diagnostics, status, and log/metric streams. Forwarded
	// without an audit record.
	ClassReadOnly
)

// String renders the class for audit records and logs.
func (c Class) String() string {
	switch c {
	case ClassMutating:
		return "mutating"
	case ClassSensitive:
		return "sensitive"
	case ClassReadOnly:
		return "read-only"
	default:
		return "unclassified"
	}
}

// methodClass maps each known MachineService full-method path to its class.
// Every one of the 54 methods present in machinery v1.14.0 is listed; a
// completeness test guards against a method silently falling out of the table.
var methodClass = map[string]Class{
	// Mutating: change node, cluster, or configuration state.
	"/machine.MachineService/ApplyConfiguration":    ClassMutating,
	"/machine.MachineService/Bootstrap":             ClassMutating,
	"/machine.MachineService/Reboot":                ClassMutating,
	"/machine.MachineService/Reset":                 ClassMutating,
	"/machine.MachineService/Shutdown":              ClassMutating,
	"/machine.MachineService/Upgrade":               ClassMutating,
	"/machine.MachineService/Rollback":              ClassMutating,
	"/machine.MachineService/Restart":               ClassMutating,
	"/machine.MachineService/ServiceStart":          ClassMutating,
	"/machine.MachineService/ServiceStop":           ClassMutating,
	"/machine.MachineService/ServiceRestart":        ClassMutating,
	"/machine.MachineService/MetaWrite":             ClassMutating,
	"/machine.MachineService/MetaDelete":            ClassMutating,
	"/machine.MachineService/ImagePull":             ClassMutating,
	"/machine.MachineService/EtcdLeaveCluster":      ClassMutating,
	"/machine.MachineService/EtcdForfeitLeadership": ClassMutating,
	"/machine.MachineService/EtcdRemoveMemberByID":  ClassMutating,
	"/machine.MachineService/EtcdRecover":           ClassMutating,
	"/machine.MachineService/EtcdDefragment":        ClassMutating,
	"/machine.MachineService/EtcdAlarmDisarm":       ClassMutating,
	"/machine.MachineService/EtcdDowngradeEnable":   ClassMutating,
	"/machine.MachineService/EtcdDowngradeCancel":   ClassMutating,

	// Sensitive: issue credentials or egress data without mutating state.
	"/machine.MachineService/Kubeconfig":                  ClassSensitive,
	"/machine.MachineService/GenerateClientConfiguration": ClassSensitive,
	"/machine.MachineService/Copy":                        ClassSensitive,
	"/machine.MachineService/Read":                        ClassSensitive,
	"/machine.MachineService/PacketCapture":               ClassSensitive,
	"/machine.MachineService/EtcdSnapshot":                ClassSensitive,

	// Read-only: diagnostics, status, log and metric streams.
	"/machine.MachineService/CPUFreqStats":          ClassReadOnly,
	"/machine.MachineService/CPUInfo":               ClassReadOnly,
	"/machine.MachineService/Containers":            ClassReadOnly,
	"/machine.MachineService/DiskStats":             ClassReadOnly,
	"/machine.MachineService/DiskUsage":             ClassReadOnly,
	"/machine.MachineService/Dmesg":                 ClassReadOnly,
	"/machine.MachineService/Events":                ClassReadOnly,
	"/machine.MachineService/Hostname":              ClassReadOnly,
	"/machine.MachineService/ImageList":             ClassReadOnly,
	"/machine.MachineService/List":                  ClassReadOnly,
	"/machine.MachineService/LoadAvg":               ClassReadOnly,
	"/machine.MachineService/Logs":                  ClassReadOnly,
	"/machine.MachineService/LogsContainers":        ClassReadOnly,
	"/machine.MachineService/Memory":                ClassReadOnly,
	"/machine.MachineService/Mounts":                ClassReadOnly,
	"/machine.MachineService/Netstat":               ClassReadOnly,
	"/machine.MachineService/NetworkDeviceStats":    ClassReadOnly,
	"/machine.MachineService/Processes":             ClassReadOnly,
	"/machine.MachineService/ServiceList":           ClassReadOnly,
	"/machine.MachineService/Stats":                 ClassReadOnly,
	"/machine.MachineService/SystemStat":            ClassReadOnly,
	"/machine.MachineService/Version":               ClassReadOnly,
	"/machine.MachineService/EtcdMemberList":        ClassReadOnly,
	"/machine.MachineService/EtcdStatus":            ClassReadOnly,
	"/machine.MachineService/EtcdAlarmList":         ClassReadOnly,
	"/machine.MachineService/EtcdDowngradeValidate": ClassReadOnly,
}

// Classify returns the class of a gRPC full-method path. An unknown method
// returns ClassUnclassified (the map's zero value).
func Classify(fullMethod string) Class {
	return methodClass[fullMethod]
}

// ShouldAudit reports whether a call of this class gets an audit record.
// Everything except plain read-only diagnostics is recorded, including
// unclassified methods, so nothing state-changing goes unrecorded.
func ShouldAudit(c Class) bool {
	return c != ClassReadOnly
}
