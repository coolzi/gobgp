// Copyright (C) 2026 Nippon Telegraph and Telephone Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package server

import (
	"math"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/internal/pkg/table"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/osrg/gobgp/v4/pkg/packet/rtr"
)

func TestRPKIRevalidationRespectsAddPathSendMax(t *testing.T) {
	r := newRPKIRevalidationTest(t, bgp.RF_IPv4_UC, false, api.PolicyDirection_POLICY_DIRECTION_EXPORT)
	r.target.fsm.familyMap.Store(map[bgp.Family]bgp.BGPAddPathMode{bgp.RF_IPv4_UC: bgp.BGP_ADD_PATH_SEND})
	r.target.fsm.lock.Lock()
	conf := r.target.fsm.pConf.ReadCopy()
	conf.AfiSafis[0].AddPaths.Config.SendMax = 1
	conf.AfiSafis[0].AddPaths.State.SendMax = 1
	r.target.fsm.pConf.Update(&conf)
	r.target.fsm.lock.Unlock()
	wire := addPathWireState{}
	r.receive(t, rtr.NewRTRCacheResponse(1))
	r.receive(t, rtr.NewRTREndOfData(1, 1))
	r.announce(t)
	wire.receive(t, r.target)
	require.Len(t, wire, 1)
	p := asPathTestPath(t, r.source, r.path.GetPrefix(), 0, 65001)
	_, err := r.s.AddPath(apiutil.AddPathRequest{Paths: []*apiutil.Path{{
		Family: p.GetFamily(), Nlri: p.GetNlri(), Attrs: p.GetFullPathAttrs(),
		PeerASN: 65003, PeerAddress: netip.MustParseAddr("192.0.2.3"), PeerID: netip.MustParseAddr("192.0.2.3"),
	}}})
	require.NoError(t, err)
	wire.receive(t, r.target)
	var candidates []*table.Path
	require.NoError(t, r.s.mgmtOperation(func() error {
		candidates = r.s.globalRib.GetPathList(table.GLOBAL_RIB_NAME, 0, []bgp.Family{bgp.RF_IPv4_UC})
		return nil
	}, true))
	require.Len(t, candidates, 2, "the RIB must retain an eligible suppressed fallback")
	require.Len(t, wire, 1, "live propagation must respect send-max before the ROA change")
	require.Equal(t, 1, r.target.advertisedRoutes([]bgp.Family{bgp.RF_IPv4_UC}))

	// Both candidates stay valid. The committed ROA still triggers a full
	// export-policy replay, which must preserve the ADD-PATH ceiling.
	r.receive(t, rtr.NewRTRCacheResponse(1))
	r.prefix(t, 65001, 1)
	r.receive(t, rtr.NewRTREndOfData(1, 2))
	wire.receive(t, r.target)
	require.Len(t, wire, 1, "RPKI replay must not advertise the suppressed fallback")
	require.Equal(t, 1, r.target.advertisedRoutes([]bgp.Family{bgp.RF_IPv4_UC}))
}

func TestRPKIRevalidationKeepsVRFNexthopInvalid(t *testing.T) {
	r := newRPKIRevalidationTest(t, bgp.RF_IPv4_UC, false, api.PolicyDirection_POLICY_DIRECTION_EXPORT)
	addVrf(t, r.s, "red", "65000:11", []string{"65000:11"}, []string{"65000:11"}, 11)
	for _, p := range []*peer{r.source, r.target} {
		p.fsm.lock.Lock()
		conf := p.fsm.pConf.ReadCopy()
		conf.Config.Vrf = "red"
		p.fsm.pConf.Update(&conf)
		p.fsm.lock.Unlock()
	}
	r.receive(t, rtr.NewRTRCacheResponse(1))
	r.receive(t, rtr.NewRTREndOfData(1, 1))
	r.announce(t)
	wire := addPathWireState{}
	wire.receive(t, r.target)
	require.Len(t, wire, 1)

	var paths []*table.Path
	require.NoError(t, r.s.mgmtOperation(func() error {
		z := &zebraClient{server: r.s, nexthopCache: make(nexthopStateCache)}
		z.nexthopCache[nexthopStateKey{11, r.path.GetNexthop()}] = math.MaxUint32
		r.s.zclient = z
		paths = r.s.globalRib.GetPathList(table.GLOBAL_RIB_NAME, 0, []bgp.Family{bgp.RF_IPv4_VPN})
		return nil
	}, true))
	require.Len(t, paths, 1)
	invalid := paths[0].Clone(false)
	invalid.IsNexthopInvalid = true
	require.NoError(t, r.s.mgmtOperation(func() error {
		r.s.propagateUpdate(nil, []*table.Path{invalid})
		paths = r.s.globalRib.GetPathList(table.GLOBAL_RIB_NAME, 0, []bgp.Family{bgp.RF_IPv4_VPN})
		return nil
	}, true))
	wire.receive(t, r.target)
	require.Empty(t, wire, "unreachable VRF nexthops must withdraw the exported route")
	require.Len(t, paths, 1)
	require.True(t, paths[0].IsNexthopInvalid, "control: the retained VPN path is unreachable before EOD")

	// Inbound replay reconstructs the VPN path from the original unicast
	// Adj-RIB-In path; it must reapply the cached VRF next-hop state.
	r.receive(t, rtr.NewRTRCacheResponse(1))
	r.prefix(t, 65001, 1)
	r.receive(t, rtr.NewRTREndOfData(1, 2))
	require.NoError(t, r.s.mgmtOperation(func() error {
		paths = r.s.globalRib.GetPathList(table.GLOBAL_RIB_NAME, 0, []bgp.Family{bgp.RF_IPv4_VPN})
		return nil
	}, true))
	require.Len(t, paths, 1)
	require.True(t, paths[0].IsNexthopInvalid, "RPKI replay must preserve cached unreachable VRF next-hop state")
	require.Empty(t, wire.receive(t, r.target), "RPKI replay must not reannounce the unreachable path")
	require.Empty(t, wire)
}
