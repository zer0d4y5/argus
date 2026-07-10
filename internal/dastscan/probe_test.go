package dastscan

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
)

// probeTarget must accept a live listener and refuse a dead one, so a DAST
// scan against a wrong port fails loudly instead of saving a silent clean run.
func TestProbeTarget(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	live := fmt.Sprintf("http://%s/", ln.Addr())
	deadPort := ln.Addr().(*net.TCPAddr).Port

	if err := probeTarget(context.Background(), live); err != nil {
		t.Errorf("live listener reported unreachable: %v", err)
	}

	ln.Close()
	dead := fmt.Sprintf("http://127.0.0.1:%d/", deadPort)
	err = probeTarget(context.Background(), dead)
	if err == nil {
		t.Fatal("closed port reported reachable")
	}
	if !strings.Contains(err.Error(), "nothing is listening") {
		t.Errorf("error %q does not explain unreachability", err)
	}
}
