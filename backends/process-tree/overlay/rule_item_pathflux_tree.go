package rule

import (
	"fmt"
	"github.com/sagernet/sing-box/adapter"
	T "github.com/sagernet/sing-box/common/pathfluxtree"
	"github.com/sagernet/sing-box/option"
	"sync"
)

var pathFluxTracker = T.New(T.NativeSource{})

type PathFluxTreeItem struct {
	root       T.Root
	unresolved bool
}

func NewPathFluxTreeItem(o option.PathFluxTreeOptions) (*PathFluxTreeItem, error) {
	r := T.Root{PID: o.PID, Started: o.Started, Sequence: o.Sequence, Name: o.Name, Path: o.Path, SelfOnly: o.SelfOnly}
	if !r.Valid() {
		return nil, T.ErrUnavailable
	}
	if r.PID != 0 {
		p, err := (T.NativeSource{}).Read(r.PID)
		if err != nil || p.Started != r.Started || p.Sequence != r.Sequence {
			return nil, T.ErrUnavailable
		}
	}
	return &PathFluxTreeItem{r, o.Unresolved}, nil
}
func (r *PathFluxTreeItem) Match(m *adapter.InboundContext) bool {
	if m.PathFluxTreeResults == nil {
		m.PathFluxTreeResults = new(sync.Map)
	}
	key := fmt.Sprintf("%d:%d:%d:%t:%q:%q", r.root.PID, r.root.Started, r.root.Sequence, r.root.SelfOnly, r.root.Name, r.root.Path)
	if known, ok := m.PathFluxTreeResults.Load(key); ok {
		result := T.Result(known.(uint8))
		if r.unresolved {
			return result == T.Unknown
		}
		return result == T.Inside
	}
	result := T.Unknown
	if m.ProcessInfo != nil {
		result = pathFluxTracker.Match(T.Identity{PID: m.ProcessInfo.ProcessID, Started: m.ProcessInfo.PathFluxStarted, Sequence: m.ProcessInfo.PathFluxSequence}, r.root)
	}
	// Positive match and its Unknown/Reject guard must share one decision. Re-reading
	// between them could turn Unknown into Inside and accidentally fall through to Direct.
	known, _ := m.PathFluxTreeResults.LoadOrStore(key, uint8(result))
	result = T.Result(known.(uint8))
	if r.unresolved {
		return result == T.Unknown
	}
	return result == T.Inside
}
func (r *PathFluxTreeItem) String() string { return "pathflux_process_tree" }
