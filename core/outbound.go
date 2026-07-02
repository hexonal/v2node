package core

import (
	"fmt"

	"encoding/json"

	vconf "github.com/wyx2685/v2node/conf"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf"
)

// build default freedom outbund
func buildDefaultOutbound(outCfg vconf.OutboundConfig) (*core.OutboundHandlerConfig, error) {
	outboundDetourConfig := &conf.OutboundDetourConfig{}
	outboundDetourConfig.Protocol = "freedom"
	outboundDetourConfig.Tag = "Default"
	//sendthrough := "origin"
	//outboundDetourConfig.SendThrough = &sendthrough

	proxySetting := &conf.FreedomConfig{
		DomainStrategy: outCfg.ResolvedDomainStrategy(),
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
	// HappyEyeballs enables RFC 8305-style racing: without it DialSystem
	// picks a single random IP from a multi-address domain and dials only
	// that one — a dead/slow IPv6 candidate hangs with nothing trying IPv4.
	// TryDelayMs/MaxConcurrentTry/DomainStrategy are now operator-tunable
	// (defaults reproduce the old UseIPv4v6 / 250ms / 4); a node with a
	// broken IPv6 egress can lower TryDelayMs or set DomainStrategy=UseIPv4.
	he := outCfg.HappyEyeballs
	sockSettings := &conf.SocketConfig{
		TFO: tfo,
		HappyEyeballsSettings: &conf.HappyEyeballsConfig{
			PrioritizeIPv6:   he.ResolvedPrioritizeIPv6(),
			TryDelayMs:       he.ResolvedTryDelayMs(),
			MaxConcurrentTry: he.ResolvedMaxConcurrentTry(),
		},
	}
	if sock := outCfg.Sockopt; sock.HasAny() {
		sockSettings.TCPKeepAliveIdle = sock.ResolvedKeepAliveIdle()
		sockSettings.TCPKeepAliveInterval = sock.ResolvedKeepAliveInterval()
		sockSettings.TCPUserTimeout = sock.ResolvedUserTimeout()
		sockSettings.TCPCongestion = sock.ResolvedCongestion()
		sockSettings.TcpMptcp = sock.ResolvedMptcp()
	}
	outboundDetourConfig.StreamSetting = &conf.StreamConfig{
		SocketSettings: sockSettings,
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
