// Copyright (C) 2015-2021 Nippon Telegraph and Telephone Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package server

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"time"

	"github.com/osrg/gobgp/v4/internal/pkg/table"
	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/osrg/gobgp/v4/pkg/packet/rtr"
)

const (
	connectRetryInterval = 30
)

func before(a, b uint32) bool {
	return int32(a-b) < 0
}

type roaEventType uint8

const (
	roaConnected roaEventType = iota
	roaDisconnected
	roaRTR
	roaLifetimeout
)

type roaEvent struct {
	EventType  roaEventType
	Src        string
	Data       []byte
	conn       *net.TCPConn
	owner      *roaClient
	generation uint64
	timestamp  time.Time
}

type roaManager struct {
	eventCh   chan *roaEvent
	clientMap map[string]*roaClient
	table     *table.ROATable
	logger    *slog.Logger
	onChange  func()
}

func newROAManager(table *table.ROATable, logger *slog.Logger) *roaManager {
	m := &roaManager{
		eventCh:   make(chan *roaEvent),
		clientMap: make(map[string]*roaClient),
		table:     table,
		logger:    logger,
	}
	return m
}

func (m *roaManager) enabled() bool {
	return len(m.clientMap) != 0
}

func (m *roaManager) notifyChange() {
	if m.onChange != nil {
		m.onChange()
	}
}

func (m *roaManager) AddServer(host string, lifetime int64) error {
	address, port, err := net.SplitHostPort(host)
	if err != nil {
		return err
	}
	if lifetime == 0 {
		lifetime = 3600
	}
	if _, ok := m.clientMap[host]; ok {
		return fmt.Errorf("ROA server exists %s", host)
	}
	m.clientMap[host] = newRoaClient(address, port, m.eventCh, lifetime)
	return nil
}

func (m *roaManager) DeleteServer(host string) error {
	client, ok := m.clientMap[host]
	if !ok {
		return fmt.Errorf("ROA server does not exist %s", host)
	}
	client.stop()
	m.table.DeleteAll(host)
	delete(m.clientMap, host)
	m.notifyChange()
	return nil
}

func (m *roaManager) Enable(address string) error {
	for network, client := range m.clientMap {
		add, _, _ := net.SplitHostPort(network)
		if add == address {
			return client.enable(client.serialNumber)
		}
	}
	return fmt.Errorf("ROA server not found %s", address)
}

func (m *roaManager) Disable(address string) error {
	for network, client := range m.clientMap {
		add, _, _ := net.SplitHostPort(network)
		if add == address {
			client.reset()
			m.table.DeleteAll(network)
			m.notifyChange()
			return nil
		}
	}
	return fmt.Errorf("ROA server not found %s", address)
}

func (m *roaManager) Reset(address string) error {
	return m.Disable(address)
}

func (m *roaManager) SoftReset(address string) error {
	for network, client := range m.clientMap {
		add, _, _ := net.SplitHostPort(network)
		if add == address {
			m.table.DeleteAll(network)
			client.stopLifetimeTimer()
			client.discardResponse()
			m.notifyChange()
			return client.softReset()
		}
	}
	return fmt.Errorf("ROA server not found %s", address)
}

func (m *roaManager) ReceiveROA() chan *roaEvent {
	return m.eventCh
}

func (c *roaClient) lifetimeout(generation uint64) {
	c.sendEvent(&roaEvent{
		EventType:  roaLifetimeout,
		Src:        c.host,
		owner:      c,
		generation: generation,
		timestamp:  time.Now(),
	})
}

func (m *roaManager) HandleROAEvent(ev *roaEvent) {
	client, y := m.clientMap[ev.Src]
	if !y || ev.owner != client {
		if ev.EventType == roaConnected && ev.conn != nil {
			ev.conn.Close()
		}
		m.logger.Error("Can't find ROA server configuration",
			slog.String("Topic", "rpki"),
			slog.Any("Key", ev.Src))
		return
	}
	if (ev.EventType == roaRTR || ev.EventType == roaDisconnected) && ev.conn != client.conn {
		return
	}
	switch ev.EventType {
	case roaDisconnected:
		m.logger.Info("ROA server is disconnected",
			slog.String("Topic", "rpki"),
			slog.Any("Key", ev.Src))
		client.state.Downtime = time.Now().Unix()
		// clear state
		client.discardResponse()
		client.state.RpkiMessages = oc.RpkiMessages{}
		client.conn = nil
		go client.tryConnect()
		// The ROAs are stale from the first disconnect on, so a session
		// that drops again before End of Data keeps the running timer.
		// End of Data stops only client.timer: a timer replaced here
		// would stay armed and delete the ROAs that were reloaded.
		if client.timer == nil {
			generation := client.lifetimeGeneration
			client.timer = time.AfterFunc(time.Duration(client.lifetime)*time.Second, func() { client.lifetimeout(generation) })
		}
	case roaConnected:
		if ev.conn == nil || client.conn != nil {
			if ev.conn != nil && ev.conn != client.conn {
				ev.conn.Close()
			}
			return
		}
		m.logger.Info("ROA server is connected",
			slog.String("Topic", "rpki"),
			slog.Any("Key", ev.Src))
		client.conn = ev.conn
		client.state.Uptime = time.Now().Unix()
		// Query and response state belongs to the manager, not its reader.
		if err := client.softReset(); err != nil {
			m.logger.Error("Failed to send initial reset query", slog.String("Host", client.host), slog.Any("Error", err))
			ev.conn.Close()
		}
		go client.established(ev.conn)
	case roaRTR:
		m.handleRTRMsg(client, &client.state, ev.Data)
	case roaLifetimeout:
		// Stop cannot retract a timeout already queued on eventCh. The
		// generation also protects a refreshed snapshot in the same session.
		if ev.owner != client || client.timer == nil || ev.generation != client.lifetimeGeneration {
			return
		}
		client.stopLifetimeTimer()
		m.logger.Info("Deleting all ROAs due to timeout",
			slog.String("Topic", "rpki"),
			slog.String("Key", client.host),
		)
		m.table.DeleteAll(client.host)
		m.notifyChange()
	}
}

func (m *roaManager) handleRTRMsg(client *roaClient, state *oc.RpkiServerState, buf []byte) {
	received := &state.RpkiMessages.RpkiReceived

	m1, err := rtr.ParseRTR(buf)
	if err == nil {
		switch msg := m1.(type) {
		case *rtr.RTRSerialNotify:
			if before(client.serialNumber, msg.SerialNumber) {
				if err := client.enable(client.serialNumber); err != nil {
					m.logger.Error("Failed to send serial query",
						slog.String("Topic", "rpki"),
						slog.String("Host", client.host),
						slog.String("Error", err.Error()),
					)
				}
			} else if client.serialNumber == msg.SerialNumber {
				// nothing
			} else {
				// should not happen. try to get the whole ROAs.
				if err := client.softReset(); err != nil {
					m.logger.Error("Failed to send soft reset",
						slog.String("Topic", "rpki"),
						slog.String("Host", client.host),
						slog.String("Error", err.Error()),
					)
				}
			}
			received.SerialNotify++
		case *rtr.RTRSerialQuery:
		case *rtr.RTRResetQuery:
		case *rtr.RTRCacheResponse:
			received.CacheResponse++
			client.discardResponse()
			client.responseActive = true
			client.responseSessionID = msg.SessionID
		case *rtr.RTRIPPrefix:
			if !client.responseActive {
				return
			}
			family := bgp.AFI_IP
			if msg.Type == rtr.RTR_IPV4_PREFIX {
				received.Ipv4Prefix++
			} else {
				family = bgp.AFI_IP6
				received.Ipv6Prefix++
			}
			roa := table.NewROA(family, msg.Prefix.AsSlice(), msg.PrefixLen, msg.MaxLen, msg.AS, client.host)
			// Keep the committed snapshot visible until the entire response
			// arrives, including withdrawals and their order.
			client.pendingROAs = append(client.pendingROAs, roaUpdate{roa: roa, withdraw: msg.Flags&1 == 0})
		case *rtr.RTREndOfData:
			received.EndOfData++
			if !client.responseActive || client.responseSessionID != msg.SessionID {
				client.discardResponse()
				return
			}
			changed := client.sessionID != msg.SessionID || client.resetQuery || len(client.pendingROAs) > 0
			// RFC 8210 5.5: a Reset Query is answered with all the
			// records the cache has, so replace the ROAs learned from
			// it, not only when the Session ID changed.
			if client.sessionID != msg.SessionID || client.resetQuery {
				m.table.DeleteAll(client.host)
			}
			client.resetQuery = false
			client.sessionID = msg.SessionID
			client.serialNumber = msg.SerialNumber
			client.stopLifetimeTimer()
			for _, update := range client.pendingROAs {
				if update.withdraw {
					m.table.Delete(update.roa)
				} else {
					m.table.Add(update.roa)
				}
			}
			client.discardResponse()
			if changed {
				m.notifyChange()
			}
		case *rtr.RTRCacheReset:
			if err := client.softReset(); err != nil {
				m.logger.Error("Failed to send soft reset",
					slog.String("Topic", "rpki"),
					slog.String("Host", client.host),
					slog.String("Error", err.Error()))
			}
			received.CacheReset++
		case *rtr.RTRErrorReport:
			received.Error++
			client.discardResponse()
		}
	} else {
		client.discardResponse()
		m.logger.Info("Failed to parse an RTR message",
			slog.String("Topic", "rpki"),
			slog.String("Host", client.host),
			slog.String("Error", err.Error()),
		)
	}
}

func (m *roaManager) GetServers() []*oc.RpkiServer {
	recordsV4, prefixesV4 := m.table.Info(bgp.RF_IPv4_UC)
	recordsV6, prefixesV6 := m.table.Info(bgp.RF_IPv6_UC)

	l := make([]*oc.RpkiServer, 0, len(m.clientMap))
	for _, client := range m.clientMap {
		state := &client.state

		if client.conn == nil {
			state.Up = false
		} else {
			state.Up = true
		}
		f := func(m map[string]uint32, key string) uint32 {
			if r, ok := m[key]; ok {
				return r
			}
			return 0
		}
		state.RecordsV4 = f(recordsV4, client.host)
		state.RecordsV6 = f(recordsV6, client.host)
		state.PrefixesV4 = f(prefixesV4, client.host)
		state.PrefixesV6 = f(prefixesV6, client.host)
		state.SerialNumber = client.serialNumber

		addr, port, _ := net.SplitHostPort(client.host)
		l = append(l, &oc.RpkiServer{
			Config: oc.RpkiServerConfig{
				Address: netip.MustParseAddr(addr),
				// Note: RpkiServerConfig.Port is uint32 type, but the TCP/UDP
				// port is 16-bit length.
				Port: func() uint32 { p, _ := strconv.ParseUint(port, 10, 16); return uint32(p) }(),
			},
			State: client.state,
		})
	}
	return l
}

type roaUpdate struct {
	roa      *table.ROA
	withdraw bool
}

type roaClient struct {
	host               string
	conn               *net.TCPConn
	state              oc.RpkiServerState
	eventCh            chan *roaEvent
	sessionID          uint16
	serialNumber       uint32
	timer              *time.Timer
	lifetime           int64
	lifetimeGeneration uint64
	responseActive     bool
	responseSessionID  uint16
	resetQuery         bool // waiting for the End of Data answering a Reset Query
	pendingROAs        []roaUpdate
	cancelfnc          context.CancelFunc
	ctx                context.Context
}

func newRoaClient(address, port string, ch chan *roaEvent, lifetime int64) *roaClient {
	ctx, cancel := context.WithCancel(context.Background())
	c := &roaClient{
		host:      net.JoinHostPort(address, port),
		eventCh:   ch,
		lifetime:  lifetime,
		ctx:       ctx,
		cancelfnc: cancel,
	}
	go c.tryConnect()
	return c
}

func (c *roaClient) enable(serial uint32) error {
	if c.conn != nil {
		r := rtr.NewRTRSerialQuery(c.sessionID, serial)
		data, _ := r.Serialize()
		_, err := c.conn.Write(data)
		if err != nil {
			return err
		}
		c.state.RpkiMessages.RpkiSent.SerialQuery++
	}
	return nil
}

func (c *roaClient) softReset() error {
	c.discardResponse()
	c.resetQuery = true
	if c.conn != nil {
		r := rtr.NewRTRResetQuery()
		data, _ := r.Serialize()
		_, err := c.conn.Write(data)
		if err != nil {
			return err
		}
		c.state.RpkiMessages.RpkiSent.ResetQuery++
	}
	return nil
}

func (c *roaClient) reset() {
	c.discardResponse()
	c.stopLifetimeTimer()
	if c.conn != nil {
		c.conn.Close()
	}
}

func (c *roaClient) discardResponse() {
	c.pendingROAs = nil
	c.responseActive = false
}

func (c *roaClient) stopLifetimeTimer() {
	c.lifetimeGeneration++
	if c.timer != nil {
		c.timer.Stop()
		c.timer = nil
	}
}

func (c *roaClient) stop() {
	c.cancelfnc()
	c.reset()
}

func (c *roaClient) tryConnect() {
	for {
		select {
		case <-c.ctx.Done():
			return
		default:
		}
		if conn, err := (&net.Dialer{}).DialContext(c.ctx, "tcp", c.host); err != nil {
			timer := time.NewTimer(connectRetryInterval * time.Second)
			select {
			case <-c.ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		} else {
			if !c.sendEvent(&roaEvent{
				EventType: roaConnected,
				Src:       c.host,
				conn:      conn.(*net.TCPConn),
				owner:     c,
				timestamp: time.Now(),
			}) {
				conn.Close()
			}
			return
		}
	}
}

func (c *roaClient) established(conn *net.TCPConn) (err error) {
	defer func() {
		conn.Close()
		c.sendEvent(&roaEvent{
			EventType: roaDisconnected,
			Src:       c.host,
			conn:      conn,
			owner:     c,
			timestamp: time.Now(),
		})
	}()

	for {
		var data []byte
		data, err = readRTRMessage(conn)
		if err != nil {
			return err
		}

		if !c.sendEvent(&roaEvent{
			EventType: roaRTR,
			Src:       c.host,
			Data:      data,
			conn:      conn,
			owner:     c,
			timestamp: time.Now(),
		}) {
			return c.ctx.Err()
		}
	}
}

func (c *roaClient) sendEvent(ev *roaEvent) bool {
	select {
	case c.eventCh <- ev:
		return true
	case <-c.ctx.Done():
		return false
	}
}

func readRTRMessage(r io.Reader) ([]byte, error) {
	header := make([]byte, rtr.RTR_MIN_LEN)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}
	totalLen := binary.BigEndian.Uint32(header[4:8])
	if totalLen < rtr.RTR_MIN_LEN {
		return nil, fmt.Errorf("too short header length %v", totalLen)
	}
	if totalLen > rtr.RTR_MAX_LEN {
		return nil, fmt.Errorf("too large header length %v", totalLen)
	}

	body := make([]byte, totalLen-rtr.RTR_MIN_LEN)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}

	return append(header, body...), nil
}
