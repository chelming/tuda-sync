package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/docker/docker/api/types/events"
	"github.com/rs/zerolog"
)

// ---- fake OPNsense (Unbound host aliases) ----------------------------------

type fakeAlias struct{ hostname, domain string }

type fakeOpn struct {
	mu              sync.Mutex
	aliases         map[string]fakeAlias // uuid -> alias
	nextID          int
	adds            int
	reconfigures    int
	failReconfigure bool
}

func (f *fakeOpn) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		path := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/unbound/"), "/")
		w.Header().Set("Content-Type", "application/json")
		switch {
		case path == "settings/search_host_alias":
			rows := []map[string]string{}
			for uuid, a := range f.aliases {
				rows = append(rows, map[string]string{"uuid": uuid, "hostname": a.hostname, "domain": a.domain})
			}
			json.NewEncoder(w).Encode(map[string]interface{}{"rows": rows, "rowCount": len(rows), "total": len(rows), "current": 1})
		case path == "settings/add_host_alias":
			var body struct {
				Alias map[string]string `json:"alias"`
			}
			json.NewDecoder(r.Body).Decode(&body)
			f.nextID++
			f.adds++
			uuid := "uuid-" + strconv.Itoa(f.nextID)
			f.aliases[uuid] = fakeAlias{body.Alias["hostname"], body.Alias["domain"]}
			json.NewEncoder(w).Encode(map[string]string{"result": "saved", "uuid": uuid})
		case strings.HasPrefix(path, "settings/del_host_alias/"):
			delete(f.aliases, strings.TrimPrefix(path, "settings/del_host_alias/"))
			json.NewEncoder(w).Encode(map[string]string{"result": "deleted"})
		case path == "service/reconfigure":
			if f.failReconfigure {
				http.Error(w, "boom", http.StatusInternalServerError)
				return
			}
			f.reconfigures++
			json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
		default:
			http.NotFound(w, r)
		}
	})
}

func (f *fakeOpn) names() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, a := range f.aliases {
		out = append(out, a.hostname+"."+a.domain)
	}
	sort.Strings(out)
	return out
}

func (f *fakeOpn) counts() (adds, reconfigures int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.adds, f.reconfigures
}

// removeOutOfBand deletes an alias behind tuda-sync's back (the OPNsense UI, a restore, ...)
func (f *fakeOpn) removeOutOfBand(fqdn string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for uuid, a := range f.aliases {
		if a.hostname+"."+a.domain == fqdn {
			delete(f.aliases, uuid)
		}
	}
}

// ---- fake Traefik API ------------------------------------------------------

type fakeTraefik struct {
	mu      sync.Mutex
	routers []TraefikRouter
}

func (f *fakeTraefik) set(hosts ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.routers = nil
	for _, h := range hosts {
		f.routers = append(f.routers, TraefikRouter{
			Name: h + "@docker", Rule: "Host(`" + h + "`)", Status: "enabled", Provider: "docker", Service: h + "@docker",
		})
	}
}

func (f *fakeTraefik) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(append([]TraefikRouter{}, f.routers...))
	})
}

// ---- harness ---------------------------------------------------------------

func TestMain(m *testing.M) {
	logger = zerolog.Nop()
	m.Run()
}

type env struct {
	opn     *fakeOpn
	traefik *fakeTraefik
	client  *OpnsenseClient
}

func setup(t *testing.T) *env {
	t.Helper()
	e := &env{
		opn:     &fakeOpn{aliases: map[string]fakeAlias{}},
		traefik: &fakeTraefik{},
	}
	opnSrv := httptest.NewTLSServer(e.opn.handler())
	trSrv := httptest.NewServer(e.traefik.handler())

	traefikApiUrl = trSrv.URL + "/api"
	traefikApiEnabled = true
	defaultProxyHostUUID = "proxy-uuid"
	traefikCacheDuration = 30 * time.Second
	enableDelayedChecks = true
	delayedRouterChecks = DelayedCheckOptions{
		InitialDelay:          20 * time.Millisecond,
		MaxDelay:              80 * time.Millisecond,
		MaxTotalDuration:      5 * time.Second,
		MaxChecks:             6,
		UseExponentialBackoff: true,
	}
	invalidateRouterCache()
	unboundDirty.Store(false)

	e.client = NewOpnsenseClient("https", strings.TrimPrefix(opnSrv.URL, "https://"), "key", "secret", true)

	t.Cleanup(func() {
		// supersede any follow-up series still sleeping, then stop the servers
		followUp.mu.Lock()
		followUp.gen++
		followUp.mu.Unlock()
		opnSrv.Close()
		trSrv.Close()
	})
	return e
}

func (e *env) scan(t *testing.T) {
	t.Helper()
	invalidateRouterCache()
	if err := scanAllTraefikRoutes(context.Background(), e.client); err != nil {
		t.Fatalf("scan failed: %v", err)
	}
}

func containerEvent(action, name string) events.Message {
	return events.Message{
		Type:   events.Type("container"),
		Action: events.Action(action),
		Actor:  events.Actor{Attributes: map[string]string{"name": name}},
	}
}

// waitFor polls until cond holds or the deadline passes
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for: %s", what)
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ---- scan behaviour --------------------------------------------------------

func TestScanCreatesAliasThenStaysQuiet(t *testing.T) {
	e := setup(t)
	e.traefik.set("echo.hlm.ing")

	e.scan(t)
	if got := e.opn.names(); !equal(got, []string{"echo.hlm.ing"}) {
		t.Fatalf("aliases after first scan = %v", got)
	}
	adds, reconfs := e.opn.counts()
	if adds != 1 || reconfs != 1 {
		t.Fatalf("first scan: adds=%d reconfigures=%d, want 1 and 1", adds, reconfs)
	}

	// Nothing changed: no new alias and, unlike before, no Unbound reconfigure
	e.scan(t)
	e.scan(t)
	adds, reconfs = e.opn.counts()
	if adds != 1 || reconfs != 1 {
		t.Fatalf("idle scans: adds=%d reconfigures=%d, want 1 and 1", adds, reconfs)
	}
}

func TestScanDeletesAliasWhoseRouterIsGone(t *testing.T) {
	e := setup(t)
	e.traefik.set("echo.hlm.ing", "other.hlm.ing")
	e.scan(t)

	e.traefik.set("other.hlm.ing")
	e.scan(t)

	if got := e.opn.names(); !equal(got, []string{"other.hlm.ing"}) {
		t.Fatalf("aliases = %v, want only other.hlm.ing", got)
	}
}

func TestAliasDeletedOutOfBandComesBack(t *testing.T) {
	e := setup(t)
	e.traefik.set("echo.hlm.ing")
	e.scan(t)

	e.opn.removeOutOfBand("echo.hlm.ing")
	e.scan(t)

	if got := e.opn.names(); !equal(got, []string{"echo.hlm.ing"}) {
		t.Fatalf("alias deleted out of band was not recreated: %v", got)
	}
}

func TestFailedReconfigureIsRetriedByNextScan(t *testing.T) {
	e := setup(t)
	e.traefik.set("echo.hlm.ing")

	e.opn.mu.Lock()
	e.opn.failReconfigure = true
	e.opn.mu.Unlock()
	invalidateRouterCache()
	if err := scanAllTraefikRoutes(context.Background(), e.client); err == nil {
		t.Fatal("expected the failed reconfigure to be reported")
	}

	e.opn.mu.Lock()
	e.opn.failReconfigure = false
	e.opn.mu.Unlock()
	e.scan(t) // the alias already exists, but Unbound still has to be told

	if _, reconfs := e.opn.counts(); reconfs != 1 {
		t.Fatalf("reconfigures = %d, want 1 (the retry)", reconfs)
	}
	e.scan(t)
	if _, reconfs := e.opn.counts(); reconfs != 1 {
		t.Fatalf("reconfigures = %d after the dirty flag cleared, want still 1", reconfs)
	}
}

// ---- the race this change is about ------------------------------------------

// A container starts: the scan in the event handler runs before Traefik has
// built the router. The follow-up scans must pick it up without waiting for
// the periodic scanner.
func TestStartEventAliasAppearsAfterTraefikCatchesUp(t *testing.T) {
	e := setup(t)

	handleDockerEvent(e.client, containerEvent("start", "echo")) // router not there yet
	if got := e.opn.names(); len(got) != 0 {
		t.Fatalf("alias created before the router existed: %v", got)
	}

	e.traefik.set("echo.hlm.ing") // Traefik catches up a moment later

	waitFor(t, "follow-up scan to create echo.hlm.ing", func() bool {
		return equal(e.opn.names(), []string{"echo.hlm.ing"})
	})
}

// The same race on the way out: the die event's scan still sees the router.
func TestDieEventAliasIsRemovedAfterTraefikCatchesUp(t *testing.T) {
	e := setup(t)
	e.traefik.set("echo.hlm.ing")
	e.scan(t)

	handleDockerEvent(e.client, containerEvent("die", "echo")) // router still listed
	if got := e.opn.names(); !equal(got, []string{"echo.hlm.ing"}) {
		t.Fatalf("alias removed before the router was gone: %v", got)
	}

	e.traefik.set() // Traefik drops the router

	waitFor(t, "follow-up scan to delete echo.hlm.ing", func() bool {
		return len(e.opn.names()) == 0
	})
}

func TestFollowUpsCanBeDisabled(t *testing.T) {
	e := setup(t)
	enableDelayedChecks = false

	handleDockerEvent(e.client, containerEvent("start", "echo"))
	e.traefik.set("echo.hlm.ing")
	time.Sleep(300 * time.Millisecond) // many follow-up intervals

	if got := e.opn.names(); len(got) != 0 {
		t.Fatalf("follow-up ran although disabled: %v", got)
	}
}

// A newer event supersedes the series still running, so a burst of events does
// not pile up scans
func TestNewEventSupersedesRunningFollowUps(t *testing.T) {
	e := setup(t)
	delayedRouterChecks.InitialDelay = 50 * time.Millisecond

	scheduleFollowUpScans("a", "start", e.client)
	followUp.mu.Lock()
	first := followUp.gen
	followUp.mu.Unlock()
	scheduleFollowUpScans("b", "start", e.client)

	if !followUpSuperseded(first) {
		t.Fatal("the first series should be superseded by the second")
	}
}

// ---- helpers ---------------------------------------------------------------

func TestNextFollowUpDelay(t *testing.T) {
	exp := DelayedCheckOptions{InitialDelay: 5 * time.Second, MaxDelay: 60 * time.Second, UseExponentialBackoff: true}
	want := []time.Duration{5 * time.Second, 10 * time.Second, 20 * time.Second, 40 * time.Second, 60 * time.Second, 60 * time.Second}
	for i, w := range want {
		if got := nextFollowUpDelay(exp, i); got != w {
			t.Errorf("exponential after check %d = %v, want %v", i, got, w)
		}
	}
	lin := DelayedCheckOptions{InitialDelay: 5 * time.Second, MaxDelay: 20 * time.Second}
	for i, w := range []time.Duration{10 * time.Second, 15 * time.Second, 20 * time.Second, 20 * time.Second} {
		if got := nextFollowUpDelay(lin, i); got != w {
			t.Errorf("linear after check %d = %v, want %v", i, got, w)
		}
	}
}

func TestGetEnvBoolDefault(t *testing.T) {
	const key = "TUDA_TEST_BOOL"
	cases := []struct {
		val  string
		def  bool
		want bool
	}{
		{"", true, true}, {"", false, false},
		{"true", false, true}, {"TRUE", false, true},
		{"false", true, false}, {"False", true, false},
		{"garbage", true, true}, {"garbage", false, false},
	}
	for _, c := range cases {
		t.Setenv(key, c.val)
		if got := getEnvBoolDefault(key, c.def); got != c.want {
			t.Errorf("value %q default %v = %v, want %v", c.val, c.def, got, c.want)
		}
	}
}
