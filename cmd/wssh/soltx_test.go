package main

import "testing"

// The explorer link is only correct if the cluster matches the endpoint, so
// the cases that matter are the four: the three public clusters and a private
// RPC, which gets no link at all rather than a wrong one.
func TestExplorerTxURL(t *testing.T) {
	const sig = "54DxBZKPwS9mBmcxiCodw5updkq2pHAu9CZF7b2tNqv7WYVjmyKDoaTcDViQDEQXNcbFUjG4W9EB19W4hqYnYhwX"

	cases := []struct {
		name     string
		endpoint string
		want     string
	}{
		{
			name:     "mainnet",
			endpoint: "https://api.mainnet-beta.solana.com",
			want:     "https://solscan.io/tx/" + sig,
		},
		{
			name:     "devnet",
			endpoint: "https://api.devnet.solana.com",
			want:     "https://solscan.io/tx/" + sig + "?cluster=devnet",
		},
		{
			name:     "testnet",
			endpoint: "https://api.testnet.solana.com",
			want:     "https://solscan.io/tx/" + sig + "?cluster=testnet",
		},
		{
			// A private RPC says nothing about which cluster it fronts, and a
			// mainnet link to a devnet transaction is a page that says the
			// transaction does not exist. No link beats a wrong one.
			name:     "a private endpoint gets no link",
			endpoint: "https://my-rpc.example.com",
			want:     "",
		},
		{
			// The host is matched case-insensitively: a URL typed by hand
			// is routinely capitalised, and DNS does not care.
			name:     "host case does not matter",
			endpoint: "https://API.Mainnet-Beta.Solana.com",
			want:     "https://solscan.io/tx/" + sig,
		},
		{
			name:     "a path on the endpoint is ignored",
			endpoint: "https://api.devnet.solana.com/rpc",
			want:     "https://solscan.io/tx/" + sig + "?cluster=devnet",
		},
		{
			name:     "something that is not a URL at all",
			endpoint: "not a url",
			want:     "",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := explorerTxURL(c.endpoint, sig); got != c.want {
				t.Errorf("explorerTxURL(%q) = %q, want %q", c.endpoint, got, c.want)
			}
		})
	}
}

// The link is derived from the endpoint that was actually used, not from the
// flag that was set: --rpc wins over --network, so a --network devnet with an
// explicit --rpc mainnet endpoint must be described as mainnet.
func TestExplorerTxURLFollowsTheEndpointNotTheFlag(t *testing.T) {
	const sig = "sig"

	if got := effectiveRPC("https://api.devnet.solana.com", "mainnet"); got != "https://api.devnet.solana.com" {
		t.Fatalf("--rpc should win over --network, got %q", got)
	}
	if got := explorerTxURL(effectiveRPC("https://api.devnet.solana.com", "mainnet"), sig); got != "https://solscan.io/tx/sig?cluster=devnet" {
		t.Errorf("the link should follow the endpoint, got %q", got)
	}
}
