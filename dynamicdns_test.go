package dynamicdns

import (
	"context"
	"net/netip"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/libdns/libdns"
	"go.uber.org/zap"
)

type fakeDNSProvider struct {
	getRecords  []libdns.Record
	appendCalls [][]libdns.Record
	deleteCalls [][]libdns.Record
	setCalls    [][]libdns.Record
}

func (f *fakeDNSProvider) GetRecords(_ context.Context, _ string) ([]libdns.Record, error) {
	return append([]libdns.Record(nil), f.getRecords...), nil
}

func (f *fakeDNSProvider) SetRecords(_ context.Context, _ string, recs []libdns.Record) ([]libdns.Record, error) {
	copied := append([]libdns.Record(nil), recs...)
	f.setCalls = append(f.setCalls, copied)
	return copied, nil
}

func (f *fakeDNSProvider) AppendRecords(_ context.Context, _ string, recs []libdns.Record) ([]libdns.Record, error) {
	copied := append([]libdns.Record(nil), recs...)
	f.appendCalls = append(f.appendCalls, copied)
	return copied, nil
}

func (f *fakeDNSProvider) DeleteRecords(_ context.Context, _ string, recs []libdns.Record) ([]libdns.Record, error) {
	copied := append([]libdns.Record(nil), recs...)
	f.deleteCalls = append(f.deleteCalls, copied)
	return copied, nil
}

type fakeIPSource struct {
	ips []netip.Addr
}

func (f fakeIPSource) GetIPs(_ context.Context, _ IPSettings) ([]netip.Addr, error) {
	return append([]netip.Addr(nil), f.ips...), nil
}

func TestLookupCurrentIPsFromDNSPreservesMultipleRecords(t *testing.T) {
	provider := &fakeDNSProvider{
		getRecords: []libdns.Record{
			libdns.Address{Name: "@", IP: netip.MustParseAddr("203.0.113.1")},
			libdns.Address{Name: "@", IP: netip.MustParseAddr("203.0.113.2")},
			libdns.Address{Name: "@", IP: netip.MustParseAddr("2001:db8::1")},
		},
	}
	app := App{
		ctx:         caddy.Context{Context: context.Background()},
		logger:      zap.NewNop(),
		dnsProvider: provider,
	}

	got, err := app.lookupCurrentIPsFromDNS(map[string][]string{"example.com": {"@"}})
	if err != nil {
		t.Fatalf("lookupCurrentIPsFromDNS() error = %v", err)
	}

	name := libdns.AbsoluteName("@", "example.com")
	if diff := len(got[name][recordTypeA]); diff != 2 {
		t.Fatalf("expected 2 A records, got %d", diff)
	}
	if diff := len(got[name][recordTypeAAAA]); diff != 1 {
		t.Fatalf("expected 1 AAAA record, got %d", diff)
	}
}

func TestLookupCurrentIPsFromDNSUnmapsIPv4InIPv6Records(t *testing.T) {
	provider := &fakeDNSProvider{
		getRecords: []libdns.Record{
			libdns.Address{Name: "@", IP: netip.MustParseAddr("::ffff:203.0.113.10")},
		},
	}
	app := App{
		ctx:         caddy.Context{Context: context.Background()},
		logger:      zap.NewNop(),
		dnsProvider: provider,
	}

	got, err := app.lookupCurrentIPsFromDNS(map[string][]string{"example.com": {"@"}})
	if err != nil {
		t.Fatalf("lookupCurrentIPsFromDNS() error = %v", err)
	}

	name := libdns.AbsoluteName("@", "example.com")
	want := netip.MustParseAddr("203.0.113.10")
	if !ipListsEqual(got[name][recordTypeA], []netip.Addr{want}) {
		t.Fatalf("expected A records %v, got %v", []netip.Addr{want}, got[name][recordTypeA])
	}
	if diff := len(normalizeIPs(got[name][recordTypeAAAA])); diff != 0 {
		t.Fatalf("expected 0 AAAA records, got %d", diff)
	}
}

func TestCheckIPAndUpdateDNSReplacesWholeRRSetWithAppenderAndDeleter(t *testing.T) {
	previousLastIPs := lastIPs
	lastIPs = nil
	t.Cleanup(func() {
		lastIPs = previousLastIPs
	})

	provider := &fakeDNSProvider{
		getRecords: []libdns.Record{
			libdns.Address{Name: "@", IP: netip.MustParseAddr("203.0.113.1")},
			libdns.Address{Name: "@", IP: netip.MustParseAddr("203.0.113.2")},
		},
	}
	app := App{
		ctx:         caddy.Context{Context: context.Background()},
		logger:      zap.NewNop(),
		dnsProvider: provider,
		ipSources: []IPSource{
			fakeIPSource{
				ips: []netip.Addr{
					netip.MustParseAddr("203.0.113.2"),
					netip.MustParseAddr("203.0.113.3"),
				},
			},
		},
		Domains: map[string][]string{
			"example.com": {"@"},
		},
	}

	app.checkIPAndUpdateDNS()

	if len(provider.setCalls) != 0 {
		t.Fatalf("expected 0 SetRecords calls, got %d", len(provider.setCalls))
	}
	if len(provider.deleteCalls) != 1 {
		t.Fatalf("expected 1 DeleteRecords call, got %d", len(provider.deleteCalls))
	}
	if len(provider.appendCalls) != 1 {
		t.Fatalf("expected 1 AppendRecords call, got %d", len(provider.appendCalls))
	}
	if len(provider.deleteCalls[0]) != 2 {
		t.Fatalf("expected 2 records in DeleteRecords call, got %d", len(provider.deleteCalls[0]))
	}
	if len(provider.appendCalls[0]) != 2 {
		t.Fatalf("expected 2 records in AppendRecords call, got %d", len(provider.appendCalls[0]))
	}

	gotIPs := make([]netip.Addr, 0, len(provider.appendCalls[0]))
	for _, rec := range provider.appendCalls[0] {
		addr, ok := rec.(libdns.Address)
		if !ok {
			t.Fatalf("expected libdns.Address record, got %T", rec)
		}
		gotIPs = append(gotIPs, addr.IP)
	}

	wantIPs := []netip.Addr{
		netip.MustParseAddr("203.0.113.2"),
		netip.MustParseAddr("203.0.113.3"),
	}
	if !ipListsEqual(gotIPs, wantIPs) {
		t.Fatalf("expected IPs %v, got %v", wantIPs, gotIPs)
	}

	name := libdns.AbsoluteName("@", "example.com")
	if !ipListsEqual(lastIPs[name][recordTypeA], wantIPs) {
		t.Fatalf("expected cached A records %v, got %v", wantIPs, lastIPs[name][recordTypeA])
	}
}

func TestCheckIPAndUpdateDNSUnmapsIPv4InIPv6BeforeSubmittingARecord(t *testing.T) {
	previousLastIPs := lastIPs
	lastIPs = nil
	t.Cleanup(func() {
		lastIPs = previousLastIPs
	})

	provider := &fakeDNSProvider{}
	app := App{
		ctx:         caddy.Context{Context: context.Background()},
		logger:      zap.NewNop(),
		dnsProvider: provider,
		ipSources: []IPSource{
			fakeIPSource{
				ips: []netip.Addr{
					netip.MustParseAddr("::ffff:203.0.113.10"),
				},
			},
		},
		Domains: map[string][]string{
			"example.com": {"@"},
		},
	}

	app.checkIPAndUpdateDNS()

	if len(provider.setCalls) != 0 {
		t.Fatalf("expected 0 SetRecords calls, got %d", len(provider.setCalls))
	}
	if len(provider.deleteCalls) != 0 {
		t.Fatalf("expected 0 DeleteRecords calls, got %d", len(provider.deleteCalls))
	}
	if len(provider.appendCalls) != 1 {
		t.Fatalf("expected 1 AppendRecords call, got %d", len(provider.appendCalls))
	}
	if len(provider.appendCalls[0]) != 1 {
		t.Fatalf("expected 1 record in AppendRecords call, got %d", len(provider.appendCalls[0]))
	}

	addr, ok := provider.appendCalls[0][0].(libdns.Address)
	if !ok {
		t.Fatalf("expected libdns.Address record, got %T", provider.appendCalls[0][0])
	}
	if got, want := recordType(addr.IP), recordTypeA; got != want {
		t.Fatalf("expected record type %s, got %s", want, got)
	}
	if got, want := addr.IP, netip.MustParseAddr("203.0.113.10"); got != want {
		t.Fatalf("expected submitted IP %s, got %s", want, got)
	}

	name := libdns.AbsoluteName("@", "example.com")
	if !ipListsEqual(lastIPs[name][recordTypeA], []netip.Addr{netip.MustParseAddr("203.0.113.10")}) {
		t.Fatalf("expected cached A record %s, got %v", "203.0.113.10", lastIPs[name][recordTypeA])
	}
}
