package server

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/internal/pkg/table"
	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/osrg/gobgp/v4/pkg/packet/rtr"
	"github.com/stretchr/testify/require"
)

type rpkiRevalidationTest struct {
	s              *BgpServer
	source, target *peer
	path           *table.Path
	cache          string
}

func newRPKIRevalidationTest(t *testing.T, family bgp.Family, routeServer bool, direction api.PolicyDirection) *rpkiRevalidationTest {
	t.Helper()
	s := NewBgpServer()
	go s.Serve()
	require.NoError(t, s.StartBgp(context.Background(), &api.StartBgpRequest{Global: &api.Global{
		Asn: 65000, RouterId: "192.0.2.254", ListenPort: -1,
	}}))
	t.Cleanup(s.Stop)
	rib := s.globalRib
	if routeServer {
		rib = s.rsRib
	}
	newPeer := func(asn uint32, address string) *peer {
		p := newPeerandInfo(t, 65000, asn, address, rib)
		p.policy = s.policy
		p.fsm.lock.Lock()
		conf := p.fsm.pConf.ReadCopy()
		conf.RouteServer.Config.RouteServerClient = routeServer
		conf.AfiSafis = []oc.AfiSafi{{State: oc.AfiSafiState{Family: family}}}
		p.fsm.pConf.Update(&conf)
		p.fsm.lock.Unlock()
		p.fsm.gConf.Config.RouterId = netip.MustParseAddr("192.0.2.254")
		if routeServer {
			p.tableId = p.ID()
		}
		p.updatePolicyIDs()
		p.adjRibIn = table.NewAdjRib(s.logger, []bgp.Family{family})
		p.fsm.familyMap.Store(map[bgp.Family]bgp.BGPAddPathMode{family: bgp.BGP_ADD_PATH_NONE})
		return p
	}
	source, target := newPeer(65001, "192.0.2.1"), newPeer(65002, "192.0.2.2")
	target.fsm.state.Store(bgp.BGP_FSM_ESTABLISHED)
	r := &rpkiRevalidationTest{s: s, source: source, target: target, cache: "192.0.2.10:323"}
	require.NoError(t, s.mgmtOperation(func() error {
		for _, p := range []*peer{source, target} {
			s.neighborMap[netip.MustParseAddr(p.ID())] = p
			if err := s.policy.SetPolicyAssignment(p.TableID(), table.POLICY_DIRECTION_IMPORT, nil, table.ROUTE_TYPE_ACCEPT); err != nil {
				return err
			}
			if err := s.policy.SetPolicyAssignment(p.TableID(), table.POLICY_DIRECTION_EXPORT, nil, table.ROUTE_TYPE_ACCEPT); err != nil {
				return err
			}
		}
		s.roaManager.clientMap[r.cache] = &roaClient{host: r.cache, cancelfnc: func() {}}
		return nil
	}, true))
	t.Cleanup(func() {
		require.NoError(t, s.mgmtOperation(func() error {
			delete(s.neighborMap, netip.MustParseAddr(source.ID()))
			delete(s.neighborMap, netip.MustParseAddr(target.ID()))
			return nil
		}, false))
		cleanInfiniteChannel(source.fsm.outgoingCh)
		cleanInfiniteChannel(target.fsm.outgoingCh)
	})
	policy := &api.Policy{Name: "reject-rpki-invalid", Statements: []*api.Statement{{
		Name: "invalid", Conditions: &api.Conditions{RpkiResult: api.ValidationState_VALIDATION_STATE_INVALID},
		Actions: &api.Actions{RouteAction: api.RouteAction_ROUTE_ACTION_REJECT},
	}}}
	require.NoError(t, s.AddPolicy(context.Background(), &api.AddPolicyRequest{Policy: policy}))
	policyID := source.importPolicyID
	if direction == api.PolicyDirection_POLICY_DIRECTION_EXPORT {
		policyID = target.exportPolicyID
	}
	require.NoError(t, s.SetPolicyAssignment(context.Background(), &api.SetPolicyAssignmentRequest{Assignment: &api.PolicyAssignment{
		Name: policyID, Direction: direction, Policies: []*api.Policy{{Name: policy.Name}}, DefaultAction: api.RouteAction_ROUTE_ACTION_ACCEPT,
	}}))
	prefix := "10.0.0.0/24"
	if family == bgp.RF_IPv6_UC {
		prefix = "2001:db8:1::/48"
	}
	r.path = asPathTestPath(t, source, prefix, 0, 65001)
	return r
}

func (r *rpkiRevalidationTest) receive(t *testing.T, msg rtr.RTRMessage) {
	t.Helper()
	data, err := msg.Serialize()
	require.NoError(t, err)
	var ev *roaEvent
	require.NoError(t, r.s.mgmtOperation(func() error {
		client := r.s.roaManager.clientMap[r.cache]
		ev = &roaEvent{EventType: roaRTR, Src: r.cache, Data: data, owner: client, conn: client.conn, timestamp: time.Now()}
		return nil
	}, true))
	select {
	case r.s.roaManager.eventCh <- ev:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out delivering RTR PDU")
	}
	// The management operation runs after Serve has handled the PDU.
	require.NoError(t, r.s.mgmtOperation(func() error { return nil }, true))
}

func (r *rpkiRevalidationTest) prefix(t *testing.T, asn uint32, flags uint8) {
	t.Helper()
	prefix := netip.MustParsePrefix(r.path.GetPrefix())
	r.receive(t, rtr.NewRTRIPPrefix(prefix.Addr(), uint8(prefix.Bits()), uint8(prefix.Bits()), asn, flags))
}

func (r *rpkiRevalidationTest) announce(t *testing.T) {
	t.Helper()
	require.NoError(t, r.s.mgmtOperation(func() error {
		accepted, withdrawn, _, _ := r.source.handleUpdate(&fsmMsg{MsgData: asPathTestUpdate(t, r.path), timestamp: time.Now()}, nil)
		r.s.propagateUpdate(r.source, append(accepted, withdrawn...))
		return nil
	}, true))
}

func (r *rpkiRevalidationTest) check(t *testing.T, count int, validation oc.RpkiValidationResultType) {
	t.Helper()
	var paths []*table.Path
	var retained int
	var status oc.RpkiValidationResultType
	require.NoError(t, r.s.mgmtOperation(func() error {
		paths = r.source.localRib.GetPathList(table.GLOBAL_RIB_NAME, 0, []bgp.Family{r.path.GetFamily()})
		retained = r.source.adjRibIn.Count([]bgp.Family{r.path.GetFamily()})
		status = r.s.roaTable.Validate(r.path).Status
		return nil
	}, true))
	require.Len(t, paths, count)
	require.Equal(t, 1, retained, "import policy must retain the original Adj-RIB-In path")
	require.Equal(t, validation, status)
}

func (r *rpkiRevalidationTest) outgoing(t *testing.T, withdraw bool) {
	t.Helper()
	select {
	case value := <-r.target.fsm.outgoingCh.Out():
		for {
			msg := value.(*fsmOutgoingMsg)
			require.NotEmpty(t, msg.Paths)
			for _, path := range msg.Paths {
				require.Equal(t, r.path.GetPrefix(), path.GetPrefix())
				require.Equal(t, withdraw, path.IsWithdraw)
			}
			select {
			case value = <-r.target.fsm.outgoingCh.Out():
			case <-time.After(25 * time.Millisecond):
				return
			}
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for downstream withdrawal=%v after RTR commit", withdraw)
	}
}

func (r *rpkiRevalidationTest) noOutgoing(t *testing.T) {
	t.Helper()
	select {
	case value := <-r.target.fsm.outgoingCh.Out():
		t.Fatalf("unexpected downstream update: %v", value)
	case <-time.After(25 * time.Millisecond):
	}
}

func TestRPKIUpdatesReevaluateExistingPaths(t *testing.T) {
	for _, family := range []bgp.Family{bgp.RF_IPv4_UC, bgp.RF_IPv6_UC} {
		for _, routeServer := range []bool{false, true} {
			for _, direction := range []api.PolicyDirection{api.PolicyDirection_POLICY_DIRECTION_IMPORT, api.PolicyDirection_POLICY_DIRECTION_EXPORT} {
				name := family.String() + "/" + map[bool]string{false: "router", true: "route-server"}[routeServer] + "/" + direction.String()
				t.Run(name, func(t *testing.T) {
					r := newRPKIRevalidationTest(t, family, routeServer, direction)
					r.receive(t, rtr.NewRTRCacheResponse(1))
					r.receive(t, rtr.NewRTREndOfData(1, 1))
					r.announce(t)
					r.outgoing(t, false)
					r.check(t, 1, oc.RPKI_VALIDATION_RESULT_TYPE_NOT_FOUND)

					r.receive(t, rtr.NewRTRCacheResponse(1))
					r.prefix(t, 65003, 1)
					r.check(t, 1, oc.RPKI_VALIDATION_RESULT_TYPE_NOT_FOUND)
					r.noOutgoing(t)
					r.receive(t, rtr.NewRTREndOfData(1, 2))
					count := 0
					if direction == api.PolicyDirection_POLICY_DIRECTION_EXPORT {
						count = 1
					}
					r.check(t, count, oc.RPKI_VALIDATION_RESULT_TYPE_INVALID)
					r.outgoing(t, true)

					r.receive(t, rtr.NewRTRCacheResponse(1))
					r.prefix(t, 65003, 0)
					r.prefix(t, 65001, 1)
					r.check(t, count, oc.RPKI_VALIDATION_RESULT_TYPE_INVALID)
					r.noOutgoing(t)
					r.receive(t, rtr.NewRTREndOfData(1, 3))
					r.check(t, 1, oc.RPKI_VALIDATION_RESULT_TYPE_VALID)
					r.outgoing(t, false)

					// A withdrawal and reannouncement in the same response must
					// not expose a transient not-found/invalid validation state.
					r.receive(t, rtr.NewRTRCacheResponse(1))
					r.prefix(t, 65001, 0)
					r.prefix(t, 65001, 1)
					r.check(t, 1, oc.RPKI_VALIDATION_RESULT_TYPE_VALID)
					r.noOutgoing(t)
					r.receive(t, rtr.NewRTREndOfData(1, 4))
					r.check(t, 1, oc.RPKI_VALIDATION_RESULT_TYPE_VALID)
					r.outgoing(t, false)

					r.receive(t, rtr.NewRTRCacheResponse(1))
					r.prefix(t, 65001, 0)
					r.prefix(t, 65003, 1)
					r.receive(t, rtr.NewRTREndOfData(1, 5))
					r.outgoing(t, true)
					r.receive(t, rtr.NewRTRCacheResponse(1))
					r.prefix(t, 65003, 0)
					r.receive(t, rtr.NewRTREndOfData(1, 6))
					r.check(t, 1, oc.RPKI_VALIDATION_RESULT_TYPE_NOT_FOUND)
					r.outgoing(t, false)
				})
			}
		}
	}
}

func TestRPKIInitialInvalidRouteIsRejected(t *testing.T) {
	for _, family := range []bgp.Family{bgp.RF_IPv4_UC, bgp.RF_IPv6_UC} {
		for _, routeServer := range []bool{false, true} {
			for _, direction := range []api.PolicyDirection{api.PolicyDirection_POLICY_DIRECTION_IMPORT, api.PolicyDirection_POLICY_DIRECTION_EXPORT} {
				name := family.String() + "/" + map[bool]string{false: "router", true: "route-server"}[routeServer] + "/" + direction.String()
				t.Run(name, func(t *testing.T) {
					r := newRPKIRevalidationTest(t, family, routeServer, direction)
					r.receive(t, rtr.NewRTRCacheResponse(1))
					r.prefix(t, 65003, 1)
					r.receive(t, rtr.NewRTREndOfData(1, 1))
					r.announce(t)
					count := 0
					if direction == api.PolicyDirection_POLICY_DIRECTION_EXPORT {
						count = 1
					}
					r.check(t, count, oc.RPKI_VALIDATION_RESULT_TYPE_INVALID)
					r.noOutgoing(t)
				})
			}
		}
	}
}

func TestRPKIRevalidationPreservesRejectedInput(t *testing.T) {
	for _, rejection := range []string{"as-loop", "own-next-hop"} {
		t.Run(rejection, func(t *testing.T) {
			r := newRPKIRevalidationTest(t, bgp.RF_IPv4_UC, false, api.PolicyDirection_POLICY_DIRECTION_IMPORT)
			if rejection == "as-loop" {
				r.path = asPathTestPath(t, r.source, r.path.GetPrefix(), 0, 65000, 65001)
			} else {
				r.path.SetNexthop(r.source.peerInfo.Load().LocalAddress)
			}
			r.announce(t)
			for serial, flags := range []uint8{1, 0} {
				r.receive(t, rtr.NewRTRCacheResponse(1))
				r.prefix(t, 65003, flags)
				r.receive(t, rtr.NewRTREndOfData(1, uint32(serial+1)))
				var raw, installed []*table.Path
				require.NoError(t, r.s.mgmtOperation(func() error {
					raw = r.source.adjRibIn.PathList([]bgp.Family{bgp.RF_IPv4_UC}, false)
					installed = r.s.globalRib.GetPathList(table.GLOBAL_RIB_NAME, 0, []bgp.Family{bgp.RF_IPv4_UC})
					return nil
				}, true))
				require.Len(t, raw, 1)
				require.True(t, raw[0].IsRejected())
				require.Empty(t, installed)
				r.noOutgoing(t)
			}
		})
	}
}

func TestRPKIRevalidationReappliesPolicyToOriginalAttributes(t *testing.T) {
	r := newRPKIRevalidationTest(t, bgp.RF_IPv4_UC, false, api.PolicyDirection_POLICY_DIRECTION_IMPORT)
	policy := &api.Policy{Name: "add-med", Statements: []*api.Statement{{
		Name: "add-med", Actions: &api.Actions{RouteAction: api.RouteAction_ROUTE_ACTION_ACCEPT, Med: &api.MedAction{Type: api.MedAction_TYPE_MOD, Value: 5}},
	}}}
	require.NoError(t, r.s.AddPolicy(context.Background(), &api.AddPolicyRequest{Policy: policy}))
	require.NoError(t, r.s.SetPolicyAssignment(context.Background(), &api.SetPolicyAssignmentRequest{Assignment: &api.PolicyAssignment{
		Name: r.source.importPolicyID, Direction: api.PolicyDirection_POLICY_DIRECTION_IMPORT,
		Policies: []*api.Policy{{Name: "reject-rpki-invalid"}, {Name: policy.Name}}, DefaultAction: api.RouteAction_ROUTE_ACTION_ACCEPT,
	}}))
	require.NoError(t, r.path.SetMed(10, true))
	r.announce(t)
	r.outgoing(t, false)
	for serial, flags := range []uint8{1, 0, 1} {
		r.receive(t, rtr.NewRTRCacheResponse(1))
		r.prefix(t, 65001, flags)
		r.receive(t, rtr.NewRTREndOfData(1, uint32(serial+1)))
		var installed, raw []*table.Path
		require.NoError(t, r.s.mgmtOperation(func() error {
			installed = r.s.globalRib.GetPathList(table.GLOBAL_RIB_NAME, 0, []bgp.Family{bgp.RF_IPv4_UC})
			raw = r.source.adjRibIn.PathList([]bgp.Family{bgp.RF_IPv4_UC}, false)
			return nil
		}, true))
		require.Len(t, installed, 1)
		med, err := installed[0].GetMed()
		require.NoError(t, err)
		require.Equal(t, uint32(15), med)
		require.Len(t, raw, 1)
		med, err = raw[0].GetMed()
		require.NoError(t, err)
		require.Equal(t, uint32(10), med, "policy replay must not accumulate mutations in Adj-RIB-In")
		r.outgoing(t, false)
	}
}

func TestRPKICachePurgesReevaluateExistingPaths(t *testing.T) {
	for _, operation := range []string{"disable", "reset", "soft-reset", "delete", "expire"} {
		t.Run(operation, func(t *testing.T) {
			r := newRPKIRevalidationTest(t, bgp.RF_IPv4_UC, false, api.PolicyDirection_POLICY_DIRECTION_IMPORT)
			r.receive(t, rtr.NewRTRCacheResponse(1))
			r.prefix(t, 65003, 1)
			r.receive(t, rtr.NewRTREndOfData(1, 1))
			r.announce(t)
			r.check(t, 0, oc.RPKI_VALIDATION_RESULT_TYPE_INVALID)
			r.noOutgoing(t)
			ctx := context.Background()
			var err error
			switch operation {
			case "disable":
				err = r.s.DisableRpki(ctx, &api.DisableRpkiRequest{Address: "192.0.2.10"})
			case "reset", "soft-reset":
				err = r.s.ResetRpki(ctx, &api.ResetRpkiRequest{Address: "192.0.2.10", Soft: operation == "soft-reset"})
			case "delete":
				err = r.s.DeleteRpki(ctx, &api.DeleteRpkiRequest{Address: "192.0.2.10", Port: 323})
			case "expire":
				err = r.s.mgmtOperation(func() error {
					client := r.s.roaManager.clientMap[r.cache]
					timer := time.NewTimer(time.Hour)
					client.timer = timer
					t.Cleanup(func() { timer.Stop() })
					r.s.roaManager.HandleROAEvent(&roaEvent{EventType: roaLifetimeout, Src: r.cache, owner: client, generation: client.lifetimeGeneration})
					return nil
				}, true)
			}
			require.NoError(t, err)
			r.check(t, 1, oc.RPKI_VALIDATION_RESULT_TYPE_NOT_FOUND)
			r.outgoing(t, false)
		})
	}
}

func TestRPKICacheRemovalPreservesOtherCache(t *testing.T) {
	for _, matchingFirst := range []bool{false, true} {
		t.Run(map[bool]string{false: "conflicting-first", true: "matching-first"}[matchingFirst], func(t *testing.T) {
			r := newRPKIRevalidationTest(t, bgp.RF_IPv4_UC, false, api.PolicyDirection_POLICY_DIRECTION_IMPORT)
			r.receive(t, rtr.NewRTRCacheResponse(1))
			r.prefix(t, 65003, 1)
			r.receive(t, rtr.NewRTREndOfData(1, 1))
			other := "192.0.2.10:3323"
			require.NoError(t, r.s.mgmtOperation(func() error {
				r.s.roaManager.clientMap[other] = &roaClient{host: other, cancelfnc: func() {}}
				return nil
			}, true))
			first := r.cache
			r.cache = other
			r.receive(t, rtr.NewRTRCacheResponse(1))
			r.prefix(t, 65001, 1)
			r.receive(t, rtr.NewRTREndOfData(1, 1))
			r.announce(t)
			r.check(t, 1, oc.RPKI_VALIDATION_RESULT_TYPE_VALID)
			r.outgoing(t, false)
			port, remaining := uint32(323), uint32(3323)
			removedKey, remainingKey := first, other
			if matchingFirst {
				port, remaining = remaining, port
				removedKey, remainingKey = other, first
			}
			require.NoError(t, r.s.DeleteRpki(context.Background(), &api.DeleteRpkiRequest{Address: "192.0.2.10", Port: port}))
			if matchingFirst {
				r.check(t, 0, oc.RPKI_VALIDATION_RESULT_TYPE_INVALID)
			} else {
				r.check(t, 1, oc.RPKI_VALIDATION_RESULT_TYPE_VALID)
			}
			r.outgoing(t, matchingFirst)
			require.NoError(t, r.s.mgmtOperation(func() error {
				if r.s.roaManager.clientMap[remainingKey] == nil || r.s.roaManager.clientMap[removedKey] != nil {
					t.Error("DeleteRpki must remove only the requested cache port")
				}
				return nil
			}, true))
			require.NoError(t, r.s.DeleteRpki(context.Background(), &api.DeleteRpkiRequest{Address: "192.0.2.10", Port: remaining}))
			r.check(t, 1, oc.RPKI_VALIDATION_RESULT_TYPE_NOT_FOUND)
			r.outgoing(t, false)
		})
	}
}

func TestRPKICacheReplacementReevaluatesExistingPaths(t *testing.T) {
	for _, cacheReset := range []bool{false, true} {
		t.Run(map[bool]string{false: "new-session", true: "cache-reset"}[cacheReset], func(t *testing.T) {
			r := newRPKIRevalidationTest(t, bgp.RF_IPv4_UC, false, api.PolicyDirection_POLICY_DIRECTION_IMPORT)
			r.receive(t, rtr.NewRTRCacheResponse(1))
			r.prefix(t, 65003, 1)
			r.receive(t, rtr.NewRTREndOfData(1, 1))
			r.announce(t)
			r.check(t, 0, oc.RPKI_VALIDATION_RESULT_TYPE_INVALID)
			session := uint16(2)
			if cacheReset {
				r.receive(t, rtr.NewRTRCacheReset())
				session = 1
			}
			r.receive(t, rtr.NewRTRCacheResponse(session))
			r.check(t, 0, oc.RPKI_VALIDATION_RESULT_TYPE_INVALID)
			r.noOutgoing(t)
			r.receive(t, rtr.NewRTREndOfData(session, 2))
			r.check(t, 1, oc.RPKI_VALIDATION_RESULT_TYPE_NOT_FOUND)
			r.outgoing(t, false)
		})
	}
}

func TestRPKIExportUpdatesAddPath(t *testing.T) {
	r := newRPKIRevalidationTest(t, bgp.RF_IPv4_UC, false, api.PolicyDirection_POLICY_DIRECTION_EXPORT)
	r.target.fsm.familyMap.Store(map[bgp.Family]bgp.BGPAddPathMode{bgp.RF_IPv4_UC: bgp.BGP_ADD_PATH_SEND})
	r.target.fsm.lock.Lock()
	conf := r.target.fsm.pConf.ReadCopy()
	conf.AfiSafis[0].AddPaths.Config.SendMax = 4
	conf.AfiSafis[0].AddPaths.State.SendMax = 4
	r.target.fsm.pConf.Update(&conf)
	r.target.fsm.lock.Unlock()
	r.receive(t, rtr.NewRTRCacheResponse(1))
	r.receive(t, rtr.NewRTREndOfData(1, 1))
	r.announce(t)
	r.outgoing(t, false)
	r.receive(t, rtr.NewRTRCacheResponse(1))
	r.prefix(t, 65003, 1)
	r.noOutgoing(t)
	r.receive(t, rtr.NewRTREndOfData(1, 2))
	r.check(t, 1, oc.RPKI_VALIDATION_RESULT_TYPE_INVALID)
	r.outgoing(t, true)
	r.receive(t, rtr.NewRTRCacheResponse(1))
	r.prefix(t, 65003, 0)
	r.receive(t, rtr.NewRTREndOfData(1, 3))
	r.check(t, 1, oc.RPKI_VALIDATION_RESULT_TYPE_NOT_FOUND)
	r.outgoing(t, false)
}

func TestROAManagerStagesOrderedUpdates(t *testing.T) {
	rt := table.NewROATable(logger)
	const cache = "192.0.2.10:323"
	client := &roaClient{host: cache}
	commits := 0
	m := &roaManager{table: rt, logger: logger, onChange: func() { commits++ }}
	receive := func(msg rtr.RTRMessage) {
		t.Helper()
		data, err := msg.Serialize()
		require.NoError(t, err)
		m.handleRTRMsg(client, &client.state, data)
	}
	prefix := func(asn uint32, flags uint8) {
		t.Helper()
		receive(rtr.NewRTRIPPrefix(netip.MustParseAddr("10.0.0.0"), 24, 24, asn, flags))
	}
	records := func() uint32 { n, _ := rt.Info(bgp.RF_IPv4_UC); return n[cache] }
	receive(rtr.NewRTRCacheResponse(1))
	prefix(65001, 1)
	receive(rtr.NewRTREndOfData(1, 1))
	require.Equal(t, 1, commits)
	receive(rtr.NewRTRCacheResponse(1))
	prefix(65001, 0)
	prefix(65001, 1)
	prefix(65002, 1)
	prefix(65002, 0)
	prefix(65003, 1)
	prefix(65003, 0)
	prefix(65003, 1)
	require.Equal(t, uint32(1), records(), "uncommitted withdrawals must preserve the previous snapshot")
	require.Equal(t, 1, commits)
	receive(rtr.NewRTREndOfData(1, 2))
	require.Equal(t, uint32(2), records())
	roas, err := rt.List(bgp.RF_IPv4_UC)
	require.NoError(t, err)
	require.Equal(t, uint32(65001), roas[0].AS)
	require.Equal(t, uint32(65003), roas[1].AS)
	require.Equal(t, 2, commits, "one response must trigger one policy reevaluation")
	// A serial response containing no changes needs no full routing sweep.
	receive(rtr.NewRTRCacheResponse(1))
	receive(rtr.NewRTREndOfData(1, 3))
	require.Equal(t, 2, commits)
}

func TestROAManagerDiscardsUncommittedUpdates(t *testing.T) {
	for _, operation := range []string{"reset", "soft-reset", "cache-reset", "cache-response", "disconnect", "error-report", "malformed", "mismatched-eod"} {
		t.Run(operation, func(t *testing.T) {
			const cache = "192.0.2.10:323"
			rt := table.NewROATable(logger)
			ctx, cancel := context.WithCancel(context.Background())
			cancel() // The disconnect case must not start a new network connection.
			client := &roaClient{host: cache, ctx: ctx, cancelfnc: cancel, lifetime: 3600}
			commits := 0
			m := &roaManager{table: rt, logger: logger, clientMap: map[string]*roaClient{cache: client}, onChange: func() { commits++ }}
			receive := func(msg rtr.RTRMessage) {
				t.Helper()
				data, err := msg.Serialize()
				require.NoError(t, err)
				m.HandleROAEvent(&roaEvent{EventType: roaRTR, Src: cache, Data: data, owner: client})
			}
			prefix := func(asn uint32, flags uint8) {
				t.Helper()
				receive(rtr.NewRTRIPPrefix(netip.MustParseAddr("10.0.0.0"), 24, 24, asn, flags))
			}
			receive(rtr.NewRTRCacheResponse(1))
			prefix(65001, 1)
			receive(rtr.NewRTREndOfData(1, 1))
			receive(rtr.NewRTRCacheResponse(1))
			prefix(65001, 0)
			prefix(65003, 1)
			switch operation {
			case "reset":
				client.reset()
			case "soft-reset":
				require.NoError(t, client.softReset())
			case "cache-reset":
				receive(rtr.NewRTRCacheReset())
			case "cache-response":
				receive(rtr.NewRTRCacheResponse(1))
			case "disconnect":
				m.HandleROAEvent(&roaEvent{EventType: roaDisconnected, Src: cache, owner: client})
				timer := client.timer
				t.Cleanup(func() { timer.Stop() })
			case "error-report":
				receive(rtr.NewRTRErrorReport(2, nil, nil))
			case "malformed":
				m.HandleROAEvent(&roaEvent{EventType: roaRTR, Src: cache, owner: client})
			case "mismatched-eod":
				receive(rtr.NewRTREndOfData(2, 2))
			}
			require.Empty(t, client.pendingROAs)
			require.Equal(t, 1, commits)
			if operation != "cache-response" {
				prefix(65004, 1)
				receive(rtr.NewRTREndOfData(1, 99))
				require.Equal(t, uint32(1), client.serialNumber, "an aborted response cannot commit a later EOD")
				require.Equal(t, 1, commits)
			}
			receive(rtr.NewRTRCacheResponse(1))
			prefix(65001, 1)
			receive(rtr.NewRTREndOfData(1, 2))
			roas, err := rt.List(bgp.RF_IPv4_UC)
			require.NoError(t, err)
			require.Len(t, roas, 1)
			require.Equal(t, uint32(65001), roas[0].AS, "an interrupted response must not leak into the next commit")
		})
	}
}

func TestROAManagerIgnoresQueuedLifetimeTimeout(t *testing.T) {
	const cache = "192.0.2.10:323"
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	client := &roaClient{host: cache, ctx: ctx, lifetime: 3600}
	t.Cleanup(client.stopLifetimeTimer)
	rt := table.NewROATable(logger)
	commits := 0
	m := &roaManager{table: rt, logger: logger, clientMap: map[string]*roaClient{cache: client}, onChange: func() { commits++ }}
	reload := func(serial uint32) {
		t.Helper()
		for _, msg := range []rtr.RTRMessage{
			rtr.NewRTRCacheResponse(1),
			rtr.NewRTRIPPrefix(netip.MustParseAddr("10.0.0.0"), 24, 24, 65001, 1),
			rtr.NewRTREndOfData(1, serial),
		} {
			data, err := msg.Serialize()
			require.NoError(t, err)
			m.handleRTRMsg(client, &client.state, data)
		}
	}
	reload(1)
	m.HandleROAEvent(&roaEvent{EventType: roaDisconnected, Src: cache, owner: client})
	stale := &roaEvent{EventType: roaLifetimeout, Src: cache, owner: client, generation: client.lifetimeGeneration}
	reload(2) // A successful response in the same cache session cancels the old timer.
	m.HandleROAEvent(stale)
	// The old event must remain stale when a subsequent disconnect arms another timer.
	m.HandleROAEvent(&roaEvent{EventType: roaDisconnected, Src: cache, owner: client})
	m.HandleROAEvent(stale)
	require.Equal(t, 2, commits)
	records, _ := rt.Info(bgp.RF_IPv4_UC)
	require.Equal(t, uint32(1), records[cache])
	require.NotNil(t, client.timer)
	m.HandleROAEvent(&roaEvent{EventType: roaLifetimeout, Src: cache, owner: client, generation: client.lifetimeGeneration})
	records, _ = rt.Info(bgp.RF_IPv4_UC)
	require.Zero(t, records[cache], "the current timeout must still expire the snapshot")
	require.Equal(t, 3, commits)
}

func rpkiTCPPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, listener.Close()) })
	client, err := net.DialTCP("tcp4", nil, listener.Addr().(*net.TCPAddr))
	require.NoError(t, err)
	t.Cleanup(func() { client.Close() })
	server, err := listener.AcceptTCP()
	require.NoError(t, err)
	t.Cleanup(func() { server.Close() })
	require.NoError(t, client.SetDeadline(time.Now().Add(3*time.Second)))
	require.NoError(t, server.SetDeadline(time.Now().Add(3*time.Second)))
	return client, server
}

func TestROAManagerIgnoresRetiredEvents(t *testing.T) {
	for _, replacedOwner := range []bool{false, true} {
		for _, kind := range []roaEventType{roaConnected, roaRTR, roaDisconnected, roaLifetimeout} {
			t.Run(fmt.Sprintf("replaced-owner=%t/event=%d", replacedOwner, kind), func(t *testing.T) {
				const cache = "192.0.2.10:323"
				oldConn, remote := rpkiTCPPair(t)
				currentConn, _ := rpkiTCPPair(t)
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				old := &roaClient{host: cache, conn: oldConn, ctx: ctx, cancelfnc: cancel}
				current := &roaClient{host: cache, conn: currentConn, ctx: ctx, cancelfnc: cancel, sessionID: 1, serialNumber: 1, lifetimeGeneration: 7}
				rt := table.NewROATable(logger)
				commits := 0
				m := &roaManager{table: rt, logger: logger, clientMap: map[string]*roaClient{cache: old}, onChange: func() { commits++ }}
				if replacedOwner {
					if kind == roaConnected {
						old.conn = nil // A queued connection was never installed in the deleted owner.
					}
					require.NoError(t, m.DeleteServer(cache))
				} else {
					old = current
				}
				m.clientMap[cache] = current
				rt.Add(table.NewROA(bgp.AFI_IP, net.IPv4(10, 0, 0, 0).To4(), 24, 24, 65001, cache))
				current.responseActive, current.responseSessionID = true, 1
				current.pendingROAs = []roaUpdate{{roa: table.NewROA(bgp.AFI_IP, net.IPv4(10, 0, 1, 0).To4(), 24, 24, 65003, cache)}}
				timer := time.NewTimer(time.Hour)
				t.Cleanup(func() { timer.Stop() })
				current.timer = timer
				commits = 0
				data, err := rtr.NewRTREndOfData(1, 99).Serialize()
				require.NoError(t, err)
				m.HandleROAEvent(&roaEvent{EventType: kind, Src: cache, owner: old, conn: oldConn, generation: 6, Data: data})
				require.Same(t, currentConn, current.conn)
				require.Same(t, timer, current.timer)
				require.Equal(t, uint32(1), current.serialNumber)
				require.Len(t, current.pendingROAs, 1)
				require.True(t, current.responseActive)
				require.Zero(t, commits)
				records, _ := rt.Info(bgp.RF_IPv4_UC)
				require.Equal(t, uint32(1), records[cache])
				if kind == roaConnected {
					_, err := remote.Read(make([]byte, 1))
					require.ErrorIs(t, err, io.EOF, "a retired connection must be closed")
				}
			})
		}
	}
}

func TestRPKIRevalidationFromRTRConnection(t *testing.T) {
	r := newRPKIRevalidationTest(t, bgp.RF_IPv4_UC, false, api.PolicyDirection_POLICY_DIRECTION_IMPORT)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, listener.Close()) })
	port := listener.Addr().(*net.TCPAddr).Port
	cache := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	require.NoError(t, r.s.AddRpki(context.Background(), &api.AddRpkiRequest{Address: "127.0.0.1", Port: uint32(port)}))
	t.Cleanup(func() {
		require.NoError(t, r.s.DeleteRpki(context.Background(), &api.DeleteRpkiRequest{Address: "127.0.0.1", Port: uint32(port)}))
	})
	require.NoError(t, listener.(*net.TCPListener).SetDeadline(time.Now().Add(3*time.Second)))
	conn, err := listener.Accept()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	require.NoError(t, conn.SetDeadline(time.Now().Add(3*time.Second)))
	data, err := readRTRMessage(conn)
	require.NoError(t, err)
	query, err := rtr.ParseRTR(data)
	require.NoError(t, err)
	require.IsType(t, &rtr.RTRResetQuery{}, query)
	write := func(msg rtr.RTRMessage) {
		t.Helper()
		data, err := msg.Serialize()
		require.NoError(t, err)
		_, err = conn.Write(data)
		require.NoError(t, err)
	}
	commit := func(serial uint32) {
		t.Helper()
		write(rtr.NewRTREndOfData(1, serial))
		require.Eventually(t, func() bool {
			var committed uint32
			err := r.s.mgmtOperation(func() error {
				committed = r.s.roaManager.clientMap[cache].serialNumber
				return nil
			}, true)
			return err == nil && committed == serial
		}, time.Second, time.Millisecond)
	}
	write(rtr.NewRTRCacheResponse(1))
	commit(1)
	r.announce(t)
	r.outgoing(t, false)
	write(rtr.NewRTRCacheResponse(1))
	write(rtr.NewRTRIPPrefix(netip.MustParseAddr("10.0.0.0"), 24, 24, 65003, 1))
	commit(2)
	r.check(t, 0, oc.RPKI_VALIDATION_RESULT_TYPE_INVALID)
	r.outgoing(t, true)
	write(rtr.NewRTRCacheResponse(1))
	write(rtr.NewRTRIPPrefix(netip.MustParseAddr("10.0.0.0"), 24, 24, 65003, 0))
	commit(3)
	r.check(t, 1, oc.RPKI_VALIDATION_RESULT_TYPE_NOT_FOUND)
	r.outgoing(t, false)
}
