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
