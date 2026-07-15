package conf

import (
	"fmt"
	"os"

	"github.com/spf13/viper"
)

const DefaultNodeRetryCount = 1
const DefaultNodeTimeout = 15

type Conf struct {
	LogConfig    LogConfig    `mapstructure:"Log"`
	NodeConfigs  []NodeConfig `mapstructure:"Nodes"`
	PprofPort    int          `mapstructure:"PprofPort"`
	PolicyConfig PolicyConfig `mapstructure:"Policy"`
	// OutboundConfig tunes the single shared freedom "Default" outbound.
	// Process-global (one Default outbound per instance); an absent "Outbound"
	// section reproduces the previous hardcoded UseIPv4v6 + HappyEyeballs{250,4}.
	OutboundConfig OutboundConfig `mapstructure:"Outbound"`
}

// PolicyConfig overrides xray-core's per-connection policy (previously
// hardcoded in core/core.go). Every field is a pointer so an unset field
// falls back to the original hardcoded default below, keeping existing
// deployments (no "Policy" section in config.json) byte-for-byte unchanged.
type PolicyConfig struct {
	// Handshake caps how long (seconds) a proxy handshake may take.
	Handshake *uint32 `mapstructure:"Handshake"`
	// ConnectionIdle closes a connection after this many seconds without
	// any upstream/downstream traffic. Was hardcoded to 120s, which is too
	// short for long-idle SSE/AI-reasoning streams (documented pain point).
	ConnectionIdle *uint32 `mapstructure:"ConnectionIdle"`
	// UplinkOnly/DownlinkOnly: once one direction closes, how long (seconds)
	// to keep the other half open before force-closing.
	UplinkOnly   *uint32 `mapstructure:"UplinkOnly"`
	DownlinkOnly *uint32 `mapstructure:"DownlinkOnly"`
	// BufferSize: per-connection buffer size in KB.
	BufferSize *int32 `mapstructure:"BufferSize"`
}

const (
	DefaultPolicyHandshake      = 4
	DefaultPolicyConnectionIdle = 120
	DefaultPolicyUplinkOnly     = 2
	DefaultPolicyDownlinkOnly   = 4
	DefaultPolicyBufferSize     = 128
)

func u32(v *uint32, def uint32) uint32 {
	if v != nil {
		return *v
	}
	return def
}

func i32(v *int32, def int32) int32 {
	if v != nil {
		return *v
	}
	return def
}

// Handshake, ConnectionIdle, UplinkOnly, DownlinkOnly, BufferSize resolve
// PolicyConfig against the original hardcoded defaults.
func (p PolicyConfig) ResolvedHandshake() uint32 {
	return u32(p.Handshake, DefaultPolicyHandshake)
}

func (p PolicyConfig) ResolvedConnectionIdle() uint32 {
	return u32(p.ConnectionIdle, DefaultPolicyConnectionIdle)
}

func (p PolicyConfig) ResolvedUplinkOnly() uint32 {
	return u32(p.UplinkOnly, DefaultPolicyUplinkOnly)
}

func (p PolicyConfig) ResolvedDownlinkOnly() uint32 {
	return u32(p.DownlinkOnly, DefaultPolicyDownlinkOnly)
}

func (p PolicyConfig) ResolvedBufferSize() int32 {
	return i32(p.BufferSize, DefaultPolicyBufferSize)
}

type LogConfig struct {
	Level  string `mapstructure:"Level"`
	Output string `mapstructure:"Output"`
	Access string `mapstructure:"Access"`
}

type NodeConfig struct {
	APIHost    string `mapstructure:"ApiHost"`
	NodeID     int    `mapstructure:"NodeID"`
	Key        string `mapstructure:"ApiKey"`
	Timeout    int    `mapstructure:"Timeout"`
	RetryCount *int   `mapstructure:"RetryCount"`
	// LocalRoutesPath points to an optional local JSON file containing an
	// array of panel.Route objects (same shape the panel's "routes" field
	// uses). Entries are merged additively with whatever routes the panel
	// API returns, so custom outbounds/routing can be defined without any
	// panel-side change. Leave empty to disable (default, no behavior change).
	LocalRoutesPath string `mapstructure:"LocalRoutesPath"`
	// InboundTFO opts this node's listener into TCP_FASTOPEN. Defaults to
	// false: on the currently deployed nodes' kernel this setsockopt call
	// fails with ENOPROTOOPT (confirmed via live logs), so enabling it there
	// only adds log noise with no benefit. Left configurable per-node in
	// case a different host/kernel supports it.
	InboundTFO bool `mapstructure:"InboundTFO"`
	// Sniffing overrides this node's inbound domain sniffing (previously
	// hardcoded to Enabled + destOverride http/tls/quic). nil, or any nil
	// field, falls back to that default so existing configs are unchanged.
	Sniffing *SniffingConfig `mapstructure:"Sniffing"`
	// Sockopt attaches extra TCP socket options to this node's inbound
	// listener. nil / all-unset attaches nothing (previous behavior).
	Sockopt *SockoptConfig `mapstructure:"Sockopt"`
	// AllowFinalMaskTcp is a node-local safety gate for the panel-configured
	// finalmask_tcp field. Defaults to false: even if a panel admin sets
	// finalmask_tcp=xmc for this node, v2node ignores it until the local
	// config.json explicitly opts in. Two independent confirmations (panel
	// field + local flag) before a brand-new, ecosystem-unproven transport
	// can change a production listener's wire protocol.
	AllowFinalMaskTcp bool `mapstructure:"AllowFinalMaskTcp"`
}

func New() *Conf {
	return &Conf{
		LogConfig: LogConfig{
			Level:  "info",
			Output: "",
			Access: "none",
		},
	}
}

func (p *Conf) LoadFromPath(filePath string) error {
	f, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("open config file error: %s", err)
	}
	defer f.Close()
	v := viper.New()
	v.SetConfigFile(filePath)
	if err := v.ReadInConfig(); err != nil {
		return fmt.Errorf("read config file error: %s", err)
	}
	if err := v.Unmarshal(p); err != nil {
		return fmt.Errorf("unmarshal config error: %s", err)
	}
	for i := range p.NodeConfigs {
		if p.NodeConfigs[i].RetryCount == nil {
			p.NodeConfigs[i].RetryCount = intPtr(DefaultNodeRetryCount)
		}
	}
	return nil
}

func intPtr(v int) *int {
	return &v
}

// ---- Workload-aware tuning (sniffing / sockopt / freedom outbound) ----
//
// Every field below is a pointer / empty-defaulting value so an absent
// section in config.json reproduces the previous hardcoded behavior
// byte-for-byte. All Resolved* methods are nil-receiver safe, so callers
// can invoke them on a nil *SniffingConfig / *SockoptConfig without a guard.

// SniffingConfig overrides the per-inbound domain sniffing that was
// hardcoded in core/inbound.go (Enabled + destOverride http/tls/quic).
type SniffingConfig struct {
	Enabled      *bool    `mapstructure:"Enabled"`
	DestOverride []string `mapstructure:"DestOverride"`
	MetadataOnly *bool    `mapstructure:"MetadataOnly"`
	RouteOnly    *bool    `mapstructure:"RouteOnly"`
}

const (
	DefaultSniffingEnabled      = true
	DefaultSniffingMetadataOnly = false
	DefaultSniffingRouteOnly    = false
)

var defaultSniffingDestOverride = []string{"http", "tls", "quic"}

func (s *SniffingConfig) ResolvedEnabled() bool {
	if s == nil || s.Enabled == nil {
		return DefaultSniffingEnabled
	}
	return *s.Enabled
}

func (s *SniffingConfig) ResolvedDestOverride() []string {
	if s == nil || len(s.DestOverride) == 0 {
		return defaultSniffingDestOverride
	}
	return s.DestOverride
}

func (s *SniffingConfig) ResolvedMetadataOnly() bool {
	if s == nil || s.MetadataOnly == nil {
		return DefaultSniffingMetadataOnly
	}
	return *s.MetadataOnly
}

func (s *SniffingConfig) ResolvedRouteOnly() bool {
	if s == nil || s.RouteOnly == nil {
		return DefaultSniffingRouteOnly
	}
	return *s.RouteOnly
}

// SockoptConfig exposes a curated subset of xray's SocketConfig TCP knobs.
// Every field defaults to "unset" (0 / "" / nil): the corresponding sockopt
// is NOT applied, keeping the xray/kernel default. This matters because some
// container kernels reject certain sockopts (see InboundTFO's ENOPROTOOPT
// note); attaching nothing by default is the safe path.
type SockoptConfig struct {
	TCPKeepAliveIdle     *int32 `mapstructure:"TcpKeepAliveIdle"`
	TCPKeepAliveInterval *int32 `mapstructure:"TcpKeepAliveInterval"`
	TCPUserTimeout       *int32 `mapstructure:"TcpUserTimeout"`
	TCPCongestion        string `mapstructure:"TcpCongestion"`
	TcpMptcp             *bool  `mapstructure:"TcpMptcp"`
}

// HasAny reports whether any knob is actually set. Callers use it to skip
// attaching a SocketConfig entirely when nothing needs tuning, so the
// no-config path stays identical to before.
func (s *SockoptConfig) HasAny() bool {
	if s == nil {
		return false
	}
	return s.TCPKeepAliveIdle != nil || s.TCPKeepAliveInterval != nil ||
		s.TCPUserTimeout != nil || s.TCPCongestion != "" || s.TcpMptcp != nil
}

func (s *SockoptConfig) ResolvedKeepAliveIdle() int32 {
	if s == nil || s.TCPKeepAliveIdle == nil {
		return 0
	}
	return *s.TCPKeepAliveIdle
}

func (s *SockoptConfig) ResolvedKeepAliveInterval() int32 {
	if s == nil || s.TCPKeepAliveInterval == nil {
		return 0
	}
	return *s.TCPKeepAliveInterval
}

func (s *SockoptConfig) ResolvedUserTimeout() int32 {
	if s == nil || s.TCPUserTimeout == nil {
		return 0
	}
	return *s.TCPUserTimeout
}

func (s *SockoptConfig) ResolvedCongestion() string {
	if s == nil {
		return ""
	}
	return s.TCPCongestion
}

func (s *SockoptConfig) ResolvedMptcp() bool {
	if s == nil || s.TcpMptcp == nil {
		return false
	}
	return *s.TcpMptcp
}

// HappyEyeballsConfig mirrors xray's HappyEyeballsConfig knobs that affect
// outbound dialing latency (RFC 8305 racing).
type HappyEyeballsConfig struct {
	PrioritizeIPv6   *bool   `mapstructure:"PrioritizeIPv6"`
	TryDelayMs       *uint64 `mapstructure:"TryDelayMs"`
	MaxConcurrentTry *uint32 `mapstructure:"MaxConcurrentTry"`
}

const (
	DefaultHappyTryDelayMs       = uint64(250)
	DefaultHappyMaxConcurrentTry = uint32(4)
	DefaultHappyPrioritizeIPv6   = false
)

func (h *HappyEyeballsConfig) ResolvedTryDelayMs() uint64 {
	if h == nil || h.TryDelayMs == nil {
		return DefaultHappyTryDelayMs
	}
	return *h.TryDelayMs
}

func (h *HappyEyeballsConfig) ResolvedMaxConcurrentTry() uint32 {
	if h == nil || h.MaxConcurrentTry == nil {
		return DefaultHappyMaxConcurrentTry
	}
	return *h.MaxConcurrentTry
}

func (h *HappyEyeballsConfig) ResolvedPrioritizeIPv6() bool {
	if h == nil || h.PrioritizeIPv6 == nil {
		return DefaultHappyPrioritizeIPv6
	}
	return *h.PrioritizeIPv6
}

// OutboundConfig tunes the single shared freedom "Default" outbound
// (core/outbound.go buildDefaultOutbound). Defaults reproduce the previous
// hardcoded UseIPv4v6 + HappyEyeballs{TryDelayMs:250, MaxConcurrentTry:4}.
type OutboundConfig struct {
	DomainStrategy string               `mapstructure:"DomainStrategy"`
	HappyEyeballs  *HappyEyeballsConfig `mapstructure:"HappyEyeballs"`
	Sockopt        *SockoptConfig       `mapstructure:"Sockopt"`
}

const DefaultOutboundDomainStrategy = "UseIPv4v6"

func (o OutboundConfig) ResolvedDomainStrategy() string {
	if o.DomainStrategy == "" {
		return DefaultOutboundDomainStrategy
	}
	return o.DomainStrategy
}
