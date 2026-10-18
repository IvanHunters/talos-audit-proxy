package audit

import "testing"

// wantClass is the expected class of every MachineService method shipped in
// machinery v1.14.0. It is the oracle for the classifier: if Talos adds a
// method and the machinery dependency is bumped, this list must be extended,
// and the completeness test below makes that omission fail loudly rather than
// letting the new method be silently treated as read-only.
var wantClass = map[string]Class{
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

	"/machine.MachineService/Kubeconfig":                  ClassSensitive,
	"/machine.MachineService/GenerateClientConfiguration": ClassSensitive,
	"/machine.MachineService/Copy":                        ClassSensitive,
	"/machine.MachineService/Read":                        ClassSensitive,
	"/machine.MachineService/PacketCapture":               ClassSensitive,
	"/machine.MachineService/EtcdSnapshot":                ClassSensitive,

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

func TestClassifyKnownMethods(t *testing.T) {
	for method, want := range wantClass {
		if got := Classify(method); got != want {
			t.Errorf("Classify(%q) = %v, want %v", method, got, want)
		}
	}
}

// TestTableCompleteness pins the table to the known Talos surface in both
// directions: every method the proxy expects is present, and the table holds
// no extra entries that the oracle does not account for.
func TestTableCompleteness(t *testing.T) {
	if len(methodClass) != len(wantClass) {
		t.Fatalf("methodClass has %d entries, oracle expects %d", len(methodClass), len(wantClass))
	}
	for method := range methodClass {
		if _, ok := wantClass[method]; !ok {
			t.Errorf("methodClass has %q which the oracle does not account for", method)
		}
	}
}

func TestClassifyUnknownMethodIsUnclassified(t *testing.T) {
	// A method from a future Talos version, not yet in the table.
	got := Classify("/machine.MachineService/SomeFutureMethod")
	if got != ClassUnclassified {
		t.Errorf("unknown method classified as %v, want unclassified", got)
	}
	if !ShouldAudit(got) {
		t.Error("unknown (unclassified) method must be audited, not dropped")
	}
}

func TestShouldAudit(t *testing.T) {
	cases := map[Class]bool{
		ClassMutating:     true,
		ClassSensitive:    true,
		ClassUnclassified: true,
		ClassReadOnly:     false,
	}
	for class, want := range cases {
		if got := ShouldAudit(class); got != want {
			t.Errorf("ShouldAudit(%v) = %v, want %v", class, got, want)
		}
	}
}
