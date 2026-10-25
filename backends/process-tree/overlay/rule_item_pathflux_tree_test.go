package rule

import (
	"github.com/sagernet/sing-box/adapter"
	T "github.com/sagernet/sing-box/common/pathfluxtree"
	"github.com/sagernet/sing-box/option"
	"testing"
)

type pathFluxTransientSource struct{ calls int }

func (p *pathFluxTransientSource) Read(pid uint32) (T.Process, error) {
	p.calls++
	if p.calls == 1 {
		return T.Process{}, T.ErrUnavailable
	}
	return T.Process{Identity: T.Identity{PID: 42, Started: 100, Sequence: 100}, ParentPID: 4, Path: `C:\Apps\root.exe`}, nil
}

func TestPathFluxUnknownDecisionCannotTurnIntoDirectBetweenRules(t *testing.T) {
	source := new(pathFluxTransientSource)
	old := pathFluxTracker
	pathFluxTracker = T.New(source)
	defer func() { pathFluxTracker = old }()
	positive, err := NewPathFluxTreeItem(option.PathFluxTreeOptions{Name: "root.exe"})
	if err != nil {
		t.Fatal(err)
	}
	guard, err := NewPathFluxTreeItem(option.PathFluxTreeOptions{Name: "root.exe", Unresolved: true})
	if err != nil {
		t.Fatal(err)
	}
	metadata := adapter.InboundContext{ProcessInfo: &adapter.ConnectionOwner{ProcessID: 42, PathFluxStarted: 100, PathFluxSequence: 100}}
	if positive.Match(&metadata) || !guard.Match(&metadata) || source.calls != 1 {
		t.Fatal("Unknown was not frozen for this flow", source.calls)
	}
	newFlow := adapter.InboundContext{ProcessInfo: metadata.ProcessInfo}
	if !positive.Match(&newFlow) || guard.Match(&newFlow) {
		t.Fatal("fresh flow did not resolve independently")
	}
}
