package core

import (
	"fmt"

	"encoding/json"

	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf"
)

// build default freedom outbund
func buildDefaultOutbound() (*core.OutboundHandlerConfig, error) {
	outboundDetourConfig := &conf.OutboundDetourConfig{}
	outboundDetourConfig.Protocol = "freedom"
	outboundDetourConfig.Tag = "Default"
	//sendthrough := "origin"
	//outboundDetourConfig.SendThrough = &sendthrough

	proxySetting := &conf.FreedomConfig{
		DomainStrategy: "UseIPv4v6",
	}
	var setting json.RawMessage
	setting, err := json.Marshal(proxySetting)
	if err != nil {
		return nil, fmt.Errorf("marshal proxy config error: %s", err)
	}
	outboundDetourConfig.Settings = &setting
	// Without an explicit sockopt, xray-core's dialer skips setsockopt()
	// entirely (transport/internet/system_dialer.go: `if sockopt != nil`),
	// so TCP_FASTOPEN_CONNECT never gets set on outbound dials no matter
	// what net.ipv4.tcp_fastopen sysctl says — the kernel capability alone
	// doesn't opt a given socket in. This is the client side (the 1 RTT
	// saved when *we* dial a destination); explicit opt-in required.
	tfo := true
	outboundDetourConfig.StreamSetting = &conf.StreamConfig{
		SocketSettings: &conf.SocketConfig{
			TFO: tfo,
			// Without this, DialSystem (transport/internet/dialer.go) picks
			// a *single random* IP from the resolved set for any domain
			// with 2+ addresses (DomainStrategy is "UseIPv4v6" above, so
			// dual-stack destinations resolve to both) and dials only that
			// one — no race, no fallback. A dead/slow IPv6 among the
			// candidates just hangs with nothing trying the working IPv4
			// alongside it. This enables RFC 8305-style racing instead:
			// try up to 4 candidates concurrently, staggered by the
			// RFC-recommended 250ms, use whichever connects first.
			HappyEyeballsSettings: &conf.HappyEyeballsConfig{
				TryDelayMs:       250,
				MaxConcurrentTry: 4,
			},
		},
	}
	return outboundDetourConfig.Build()
}

// build block outbund
func buildBlockOutbound() (*core.OutboundHandlerConfig, error) {
	outboundDetourConfig := &conf.OutboundDetourConfig{}
	outboundDetourConfig.Protocol = "blackhole"
	outboundDetourConfig.Tag = "block"
	return outboundDetourConfig.Build()
}

// build dns outbound
func buildDnsOutbound() (*core.OutboundHandlerConfig, error) {
	outboundDetourConfig := &conf.OutboundDetourConfig{}
	outboundDetourConfig.Protocol = "dns"
	outboundDetourConfig.Tag = "dns_out"
	return outboundDetourConfig.Build()
}
