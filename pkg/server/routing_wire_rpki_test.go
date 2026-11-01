package server

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/packet/rtr"
	"github.com/stretchr/testify/require"
)

func wireRTRRead(t *testing.T, c net.Conn, want byte) {
	t.Helper()
	require.NoError(t, c.SetReadDeadline(time.Now().Add(5*time.Second)))
	h := make([]byte, 8)
	_, err := io.ReadFull(c, h)
	require.NoError(t, err)
	require.Equal(t, byte(0), h[0])
	require.Equal(t, want, h[1])
	size := int(binary.BigEndian.Uint32(h[4:]))
	require.GreaterOrEqual(t, size, 8)
	require.LessOrEqual(t, size, 4096)
	_, err = io.CopyN(io.Discard, c, int64(size-8))
	require.NoError(t, err)
}

func wireRTRSend(t *testing.T, c net.Conn, msgs ...rtr.RTRMessage) {
	t.Helper()
	require.NoError(t, c.SetWriteDeadline(time.Now().Add(3*time.Second)))
	for _, m := range msgs {
		data, err := m.Serialize()
		require.NoError(t, err)
		_, err = io.Copy(c, bytes.NewReader(data))
		require.NoError(t, err)
	}
}

func TestRoutingWireRPKIRevalidation(t *testing.T) {
	for _, beforeRoute := range []bool{false, true} {
		t.Run(fmt.Sprintf("vrp-before-route-%v", beforeRoute), func(t *testing.T) {
			ctx := context.Background()
			s, port := wireServer(t)
			policy := &api.Policy{Name: "wire-reject-invalid", Statements: []*api.Statement{{Name: "invalid", Conditions: &api.Conditions{RpkiResult: api.ValidationState_VALIDATION_STATE_INVALID}, Actions: &api.Actions{RouteAction: api.RouteAction_ROUTE_ACTION_REJECT}}}}
			require.NoError(t, s.AddPolicy(ctx, &api.AddPolicyRequest{Policy: policy}))
			require.NoError(t, s.SetPolicyAssignment(ctx, &api.SetPolicyAssignmentRequest{Assignment: &api.PolicyAssignment{Name: "global", Direction: api.PolicyDirection_POLICY_DIRECTION_IMPORT, Policies: []*api.Policy{{Name: policy.Name}}, DefaultAction: api.RouteAction_ROUTE_ACTION_ACCEPT}}))
			listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, listener.Close()) })
			require.NoError(t, listener.SetDeadline(time.Now().Add(5*time.Second)))
			rpkiPort := uint32(listener.Addr().(*net.TCPAddr).Port)
			require.NoError(t, s.AddRpki(ctx, &api.AddRpkiRequest{Address: "127.0.0.1", Port: rpkiPort}))
			t.Cleanup(func() {
				require.NoError(t, s.DeleteRpki(ctx, &api.DeleteRpkiRequest{Address: "127.0.0.1", Port: rpkiPort}))
			})
			cache, err := listener.Accept()
			require.NoError(t, err)
			t.Cleanup(func() { cache.Close() })
			wireRTRRead(t, cache, 2)
			wireRTRSend(t, cache, rtr.NewRTRCacheResponse(1), rtr.NewRTREndOfData(1, 1))
			source := wirePeer(t, s, port, "127.0.0.2", 65001, 0)
			observer := wirePeer(t, s, port, "127.0.0.3", 65002, 0)
			state := map[uint32]bool{}
			updateVRP := func(announce bool, serial uint32, end bool) {
				wireRTRSend(t, cache, rtr.NewRTRSerialNotify(1, serial))
				wireRTRRead(t, cache, 1)
				flag := uint8(0)
				if announce {
					flag = 1
				}
				wireRTRSend(t, cache, rtr.NewRTRCacheResponse(1), rtr.NewRTRIPPrefix(netip.MustParseAddr("10.231.0.0"), 24, 24, 65099, flag))
				if end {
					wireRTRSend(t, cache, rtr.NewRTREndOfData(1, serial))
				}
			}
			if beforeRoute {
				updateVRP(true, 2, true)
				require.Eventually(t, func() bool {
					n := 0
					err := s.ListRpkiTable(ctx, &api.ListRpkiTableRequest{Family: &api.Family{Afi: api.Family_AFI_IP, Safi: api.Family_SAFI_UNICAST}}, func(*api.Roa) { n++ })
					return err == nil && n == 1
				}, 3*time.Second, 10*time.Millisecond)
			}
			wireUpdate(t, source, false, 65001)
			if beforeRoute {
				wirePathCount(t, s, api.TableType_TABLE_TYPE_ADJ_IN, "127.0.0.2", 1)
				wireCollect(t, observer, state, false, 500*time.Millisecond)
				require.Empty(t, state)
				wireRIBCount(t, s, 0)
				return
			}
			wireRIBCount(t, s, 1)
			wireCollect(t, observer, state, false, 300*time.Millisecond)
			require.Len(t, state, 1)
			updateVRP(true, 2, false)
			// Wait until the manager consumed the prefix, while EOD 2 is still
			// withheld; wire silence alone could just mean a delayed RTR reader.
			require.Eventually(t, func() bool {
				consumed := false
				err := s.ListRpki(ctx, &api.ListRpkiRequest{}, func(cache *api.Rpki) {
					if cache.Conf.Address == "127.0.0.1" && cache.Conf.RemotePort == rpkiPort {
						consumed = cache.State.ReceivedIpv4 == 1 && cache.State.Serial == 1 && cache.State.EndOfData == 1
					}
				})
				return err == nil && consumed
			}, 3*time.Second, 10*time.Millisecond)
			pendingCount := 0
			require.NoError(t, s.ListRpkiTable(ctx, &api.ListRpkiTableRequest{Family: &api.Family{Afi: api.Family_AFI_IP, Safi: api.Family_SAFI_UNICAST}}, func(*api.Roa) { pendingCount++ }))
			require.Zero(t, pendingCount, "uncommitted VRP must remain outside the validation table")
			_, w := wireCollect(t, observer, state, false, 300*time.Millisecond)
			require.Zero(t, w, "VRP batch must not re-evaluate before EndOfData")
			require.Len(t, state, 1)
			wireRTRSend(t, cache, rtr.NewRTREndOfData(1, 2))
			_, w = wireCollect(t, observer, state, false, 1500*time.Millisecond)
			require.Positive(t, w, "RTR invalidation must withdraw without soft reset")
			require.Empty(t, state)
			wireRIBCount(t, s, 0)
			updateVRP(false, 3, true)
			a, _ := wireCollect(t, observer, state, false, 1500*time.Millisecond)
			require.Positive(t, a, "VRP removal must recover retained input route")
			require.Len(t, state, 1)
			wireRIBCount(t, s, 1)
		})
	}
}
