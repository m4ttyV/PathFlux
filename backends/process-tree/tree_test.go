package processtree

import (
	"os"
	"testing"
)

type memory map[uint32]Process

func (m memory) Read(pid uint32) (Process, error) {
	p, ok := m[pid]
	if !ok {
		return Process{}, ErrUnavailable
	}
	return p, nil
}
func proc(pid uint32, started uint64, parent uint32, path string) Process {
	return Process{Identity{pid, started, started}, parent, path}
}

func TestDynamicChildrenAndUnrelatedSameExecutable(t *testing.T) {
	m := memory{10: proc(10, 100, 4, `C:\Apps\root.exe`), 20: proc(20, 200, 10, `C:\Apps\worker.exe`), 30: proc(30, 300, 4, `C:\Apps\worker.exe`)}
	tracker := New(m)
	root := Root{PID: 10, Started: 100, Sequence: 100}
	if tracker.Match(m[20].Identity, root) != Inside {
		t.Fatal("child missed")
	}
	if tracker.Match(m[30].Identity, root) != Outside {
		t.Fatal("unrelated identical executable included")
	}
	m[40] = proc(40, 400, 20, `C:\Other\grandchild.exe`)
	if tracker.Match(m[40].Identity, root) != Inside {
		t.Fatal("new grandchild missed")
	}
}

func TestPidReuseDoesNotInheritRule(t *testing.T) {
	m := memory{10: proc(10, 100, 4, `C:\Apps\root.exe`), 20: proc(20, 200, 10, `C:\Apps\worker.exe`)}
	tracker := New(m)
	root := Root{PID: 10, Started: 100, Sequence: 100}
	if tracker.Match(m[20].Identity, root) != Inside {
		t.Fatal("setup")
	}
	m[20] = proc(20, 300, 4, `C:\Apps\worker.exe`)
	if tracker.Match(m[20].Identity, root) != Outside {
		t.Fatal("reused PID inherited cached lineage")
	}
	if tracker.Match(Identity{20, 200, 200}, root) != Unknown {
		t.Fatal("stale owner accepted")
	}
}

func TestParentExitPreservesProvenLineage(t *testing.T) {
	m := memory{10: proc(10, 100, 4, `C:\Apps\root.exe`), 20: proc(20, 200, 10, `C:\Apps\worker.exe`)}
	tracker := New(m)
	root := Root{PID: 10, Started: 100, Sequence: 100}
	if tracker.Match(m[20].Identity, root) != Inside {
		t.Fatal("setup")
	}
	delete(m, 10)
	if tracker.Match(m[20].Identity, root) != Inside {
		t.Fatal("lost proven orphan")
	}
	m[30] = proc(30, 300, 20, `C:\Apps\new.exe`)
	if tracker.Match(m[30].Identity, root) != Inside {
		t.Fatal("lost new child of proven orphan")
	}
}

func TestMissingReusedAndCyclicParentsAreUnknown(t *testing.T) {
	for _, parent := range []Process{proc(10, 300, 4, `C:\Apps\root.exe`), proc(10, 100, 20, `C:\Apps\root.exe`), {}} {
		m := memory{20: proc(20, 200, 10, `C:\Apps\worker.exe`)}
		if parent.PID != 0 {
			m[10] = parent
		}
		if New(m).Match(m[20].Identity, Root{PID: 50, Started: 50, Sequence: 50}) != Unknown {
			t.Fatal("unproven lineage treated as outside")
		}
	}
}

func TestRootSelectorsAndInvalidRoots(t *testing.T) {
	m := memory{10: proc(10, 100, 4, `C:\Apps\Root.exe`)}
	tracker := New(m)
	for _, root := range []Root{{Name: "ROOT.EXE"}, {Path: `c:\apps\root.exe`}, {PID: 10, Started: 100, Sequence: 100}} {
		if tracker.Match(m[10].Identity, root) != Inside {
			t.Fatal("selector mismatch", root)
		}
	}
	for _, root := range []Root{{}, {PID: 10}, {Started: 100, Sequence: 100}, {Name: `C:\root.exe`}, {PID: 10, Started: 100, Sequence: 100, Name: "root.exe"}} {
		if tracker.Match(m[10].Identity, root) != Unknown {
			t.Fatal("invalid root accepted", root)
		}
	}
}

func TestNativeCurrentIdentity(t *testing.T) {
	p, err := (NativeSource{}).Read(uint32(os.Getpid()))
	if err != nil || p.PID != uint32(os.Getpid()) || p.Started == 0 || p.Path == "" || p.ParentPID == 0 {
		t.Fatal("native identity unavailable", p, err)
	}
}

func TestClockRollbackCannotClassifyChildAsOutside(t *testing.T) {
	m := memory{10: proc(10, 1000, 4, `C:\Apps\root.exe`), 20: proc(20, 900, 10, `C:\Apps\worker.exe`)}
	p := m[20]
	p.Sequence = 2000
	m[20] = p
	if New(m).Match(p.Identity, Root{PID: 10, Started: 1000, Sequence: 1000}) != Inside {
		t.Fatal("UTC rollback bypassed root")
	}
}

func TestProvenOrphanSurvivesUnavailableHigherAncestor(t *testing.T) {
	m := memory{10: proc(10, 100, 99, `C:\Apps\root.exe`), 20: proc(20, 200, 10, `C:\Apps\worker.exe`)}
	tree := New(m)
	root := Root{PID: 10, Started: 100, Sequence: 100}
	if tree.Match(m[20].Identity, root) != Inside {
		t.Fatal("setup")
	}
	delete(m, 10)
	if tree.Match(m[20].Identity, root) != Inside {
		t.Fatal("lost proven partial lineage")
	}
	m[30] = proc(30, 300, 20, `C:\Apps\new.exe`)
	if tree.Match(m[30].Identity, root) != Inside {
		t.Fatal("lost new child of proven orphan")
	}
}

func TestReusedPidAndCreationTimeCannotInheritCachedTree(t *testing.T) {
	m := memory{10: proc(10, 100, 4, `C:\Apps\root.exe`), 20: proc(20, 200, 10, `C:\Apps\worker.exe`)}
	tree := New(m)
	root := Root{PID: 10, Started: 100, Sequence: 100}
	if tree.Match(m[20].Identity, root) != Inside {
		t.Fatal("setup")
	}
	p := m[20]
	p.Sequence = 300
	p.ParentPID = 4
	m[20] = p
	if tree.Match(p.Identity, root) != Outside {
		t.Fatal("reused PID and UTC stamp inherited cached identity")
	}
}

func TestSelfOnlyPidExcludesItsChild(t *testing.T) {
	m := memory{10: proc(10, 100, 4, `C:\Apps\root.exe`), 20: proc(20, 200, 10, `C:\Apps\root.exe`)}
	tree := New(m)
	root := Root{PID: 10, Started: 100, Sequence: 100, SelfOnly: true}
	if tree.Match(m[10].Identity, root) != Inside || tree.Match(m[20].Identity, root) != Outside {
		t.Fatal("self-only rule included child")
	}
}

func TestTemporalExclusionDoesNotRequireProtectedAncestors(t *testing.T) {
	m := memory{20: proc(20, 200, 10, `C:\Apps\worker.exe`), 10: proc(10, 50, 99, `C:\Apps\launcher.exe`)}
	if New(m).Match(m[20].Identity, Root{PID: 30, Started: 100, Sequence: 100}) != Outside {
		t.Fatal("older ancestor cannot descend from newer root")
	}
}

func TestCachedChainsCannotExceedDepthLimit(t *testing.T) {
	m := memory{10: proc(10, 10, 4, `C:\Apps\root.exe`)}
	tree := New(m)
	root := Root{PID: 10, Started: 10, Sequence: 10}
	for i := uint32(11); i < 300; i++ {
		m[i] = proc(i, uint64(i), i-1, `C:\Apps\worker.exe`)
		result := tree.Match(m[i].Identity, root)
		if i <= 137 && result != Inside {
			t.Fatal("shallow chain missed", i)
		}
		if i > 137 && result != Unknown {
			t.Fatal("deep chain escaped limit", i, result)
		}
	}
	for _, known := range tree.cache {
		if len(known.chain) > 128 {
			t.Fatal("unbounded cached chain")
		}
	}
}
