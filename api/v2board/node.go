package panel

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"encoding/json"

	"github.com/sirupsen/logrus"
)

// Security type
const (
	None    = 0
	Tls     = 1
	Reality = 2
)

type NodeInfo struct {
	Id           int
	Type         string
	Security     int
	PushInterval time.Duration
	PullInterval time.Duration
	Tag          string
	Common       *CommonNode
}

type CommonNode struct {
	Protocol   string      `json:"protocol"`
	ListenIP   string      `json:"listen_ip"`
	ServerPort int         `json:"server_port"`
	Routes     []Route     `json:"routes"`
	BaseConfig *BaseConfig `json:"base_config"`
	//vless vmess trojan
	Tls                  int         `json:"tls"`
	TlsSettings          TlsSettings `json:"tls_settings"`
	CertInfo             *CertInfo
	Network              string          `json:"network"`
	NetworkSettings      json.RawMessage `json:"network_settings"`
	TrustedXForwardedFor []string        `json:"trusted_x_forwarded_for"`
	Encryption           string          `json:"encryption"`
	EncryptionSettings   EncSettings     `json:"encryption_settings"`
	ServerName           string          `json:"server_name"`
	Flow                 string          `json:"flow"`
	// FinalMaskTcp is the TCP-layer finalmask type ("xmc" is the only value
	// currently wired end-to-end). Empty/absent = no finalmask attached,
	// i.e. today's behavior, unchanged.
	FinalMaskTcp         string      `json:"finalmask_tcp"`
	FinalMaskTcpSettings XmcSettings `json:"finalmask_tcp_settings"`
	//shadowsocks
	Cipher    string `json:"cipher"`
	ServerKey string `json:"server_key"`
	//tuic
	CongestionControl string `json:"congestion_control"`
	ZeroRTTHandshake  bool   `json:"zero_rtt_handshake"`
	//anytls
	PaddingScheme []string `json:"padding_scheme,omitempty"`
	//hysteria hysteria2
	UpMbps                  int    `json:"up_mbps"`
	DownMbps                int    `json:"down_mbps"`
	Obfs                    string `json:"obfs"`
	ObfsPassword            string `json:"obfs_password"`
	Ignore_Client_Bandwidth bool   `json:"ignore_client_bandwidth"`
}

type Route struct {
	Id          int      `json:"id"`
	Match       []string `json:"match"`
	Action      string   `json:"action"`
	ActionValue *string  `json:"action_value"`
}

var localRoutesCache sync.Map // path -> *localRoutesCacheEntry

type localRoutesCacheEntry struct {
	modTime time.Time
	routes  []Route
}

// loadLocalRoutes reads a JSON file containing an array of Route objects,
// in the same shape the panel's "routes" field uses. This lets an operator
// define custom outbounds/routing (e.g. route a domain to a local SOCKS5)
// purely via a local file, without any panel-side support.
//
// GetNodeInfo (and therefore this function) runs on every pull_interval
// tick, so the parsed result is cached by mtime to avoid re-reading and
// re-parsing the file on every poll when it hasn't changed.
func loadLocalRoutes(path string) ([]Route, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat file: %w", err)
	}
	if cached, ok := localRoutesCache.Load(path); ok {
		entry := cached.(*localRoutesCacheEntry)
		if entry.modTime.Equal(fi.ModTime()) {
			return entry.routes, nil
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}
	var routes []Route
	if err := json.Unmarshal(data, &routes); err != nil {
		return nil, fmt.Errorf("parse json: %w", err)
	}
	localRoutesCache.Store(path, &localRoutesCacheEntry{modTime: fi.ModTime(), routes: routes})
	return routes, nil
}

type BaseConfig struct {
	PushInterval           any `json:"push_interval"`
	PullInterval           any `json:"pull_interval"`
	DeviceOnlineMinTraffic int `json:"device_online_min_traffic"`
	NodeReportMinTraffic   int `json:"node_report_min_traffic"`
}

type TlsSettings struct {
	ServerName       string   `json:"server_name"`
	ServerNames      []string `json:"server_names"`
	Dest             string   `json:"dest"`
	ServerPort       string   `json:"server_port"`
	ShortId          string   `json:"short_id"`
	ShortIds         []string `json:"short_ids"`
	PrivateKey       string   `json:"private_key"`
	Mldsa65Seed      string   `json:"mldsa65Seed"`
	Xver             uint64   `json:"xver,string"`
	CertMode         string   `json:"cert_mode"`
	CertFile         string   `json:"cert_file"`
	KeyFile          string   `json:"key_file"`
	Provider         string   `json:"provider"`
	DNSEnv           string   `json:"dns_env"`
	RejectUnknownSni string   `json:"reject_unknown_sni"`
}

type CertInfo struct {
	CertMode         string
	CertFile         string
	KeyFile          string
	Email            string
	CertDomain       string
	DNSEnv           map[string]string
	Provider         string
	RejectUnknownSni bool
}

type EncSettings struct {
	Mode          string `json:"mode"`
	Ticket        string `json:"ticket"`
	ServerPadding string `json:"server_padding"`
	PrivateKey    string `json:"private_key"`
}

// XmcSettings mirrors xtls/xray-core/infra/conf.XMC{Hostname, Usernames,
// Password} field-for-field so it can be json.Marshal'd straight into the
// finalmask.tcp[].settings blob Xray-core expects.
type XmcSettings struct {
	Hostname  string   `json:"hostname"`
	Usernames []string `json:"usernames"`
	Password  string   `json:"password"`
}

// localRoutesChanged reports whether c.LocalRoutesPath's mtime differs from
// the last time GetNodeInfo checked it, and updates the tracked mtime.
// It intentionally does not read/parse the file (loadLocalRoutes already
// caches that); it only needs a cheap signal so a local-only edit isn't
// masked by the panel's own "unchanged" short-circuits below.
func (c *Client) localRoutesChanged() bool {
	if c.LocalRoutesPath == "" {
		return false
	}
	fi, err := os.Stat(c.LocalRoutesPath)
	if err != nil {
		// Missing/unreadable file: nothing to force a refresh for.
		return false
	}
	if c.localRoutesModTimeSet && fi.ModTime().Equal(c.localRoutesModTime) {
		return false
	}
	c.localRoutesModTime = fi.ModTime()
	c.localRoutesModTimeSet = true
	return true
}

func (c *Client) GetNodeInfo(ctx context.Context) (node *NodeInfo, err error) {
	const path = "/api/v2/server/config"
	// Checked up front (and unconditionally, even on a 304/hash-unchanged
	// panel response below) so that editing only the local routes file
	// still triggers a rebuild on the next poll, without requiring a
	// v2node restart.
	forceRefresh := c.localRoutesChanged()
	req := c.client.R().SetContext(ctx).ForceContentType("application/json")
	if !forceRefresh {
		// Only send the conditional header when we don't need a guaranteed
		// full body back: a forced refresh must not risk a bodyless 304.
		req.SetHeader("If-None-Match", c.nodeEtag)
	}
	r, err := req.Get(path)
	if err != nil {
		return nil, err
	}
	if r == nil {
		return nil, fmt.Errorf("received nil response")
	}

	if r.StatusCode() == 304 && !forceRefresh {
		return nil, nil
	}
	hash := sha256.Sum256(r.Body())
	newBodyHash := hex.EncodeToString(hash[:])
	if c.responseBodyHash == newBodyHash && !forceRefresh {
		return nil, nil
	}
	c.responseBodyHash = newBodyHash
	c.nodeEtag = r.Header().Get("ETag")

	if r != nil {
		defer func() {
			if r.RawBody() != nil {
				r.RawBody().Close()
			}
		}()
	} else {
		return nil, fmt.Errorf("received nil response")
	}
	node = &NodeInfo{
		Id: c.NodeId,
	}
	// parse protocol params
	cm := &CommonNode{}
	err = json.Unmarshal(r.Body(), cm)
	if err != nil {
		return nil, fmt.Errorf("decode node params error: %s", err)
	}
	if c.LocalRoutesPath != "" {
		localRoutes, err := loadLocalRoutes(c.LocalRoutesPath)
		if err != nil {
			logrus.Warnf("load local routes from %s failed (ignored): %s", c.LocalRoutesPath, err)
		} else {
			cm.Routes = append(cm.Routes, localRoutes...)
		}
	}
	switch cm.Protocol {
	case "vmess", "trojan", "hysteria2", "tuic", "anytls", "vless":
		node.Type = cm.Protocol
		node.Security = cm.Tls
	case "shadowsocks":
		node.Type = cm.Protocol
		node.Security = 0
	default:
		return nil, fmt.Errorf("unsupport protocol: %s", cm.Protocol)
	}
	node.Tag = fmt.Sprintf("[%s]-%s:%d", c.APIHost, node.Type, node.Id)
	cf := cm.TlsSettings.CertFile
	kf := cm.TlsSettings.KeyFile
	if cf == "" {
		cf = filepath.Join("/etc/v2node/", cm.Protocol+strconv.Itoa(c.NodeId)+".cer")
	}
	if kf == "" {
		kf = filepath.Join("/etc/v2node/", cm.Protocol+strconv.Itoa(c.NodeId)+".key")
	}
	cm.CertInfo = &CertInfo{
		CertMode:         cm.TlsSettings.CertMode,
		CertFile:         cf,
		KeyFile:          kf,
		Email:            "node@v2board.com",
		CertDomain:       cm.TlsSettings.PrimaryServerName(),
		DNSEnv:           make(map[string]string),
		Provider:         cm.TlsSettings.Provider,
		RejectUnknownSni: cm.TlsSettings.RejectUnknownSni == "1",
	}
	if cm.CertInfo.CertMode == "dns" && cm.TlsSettings.DNSEnv != "" {
		envs := strings.Split(cm.TlsSettings.DNSEnv, ",")
		for _, env := range envs {
			kv := strings.SplitN(env, "=", 2)
			if len(kv) == 2 {
				cm.CertInfo.DNSEnv[kv[0]] = kv[1]
			}
		}
	}

	// set interval
	node.PushInterval = intervalToTime(cm.BaseConfig.PushInterval)
	node.PullInterval = intervalToTime(cm.BaseConfig.PullInterval)

	node.Common = cm

	return node, nil
}

func intervalToTime(i interface{}) time.Duration {
	switch reflect.TypeOf(i).Kind() {
	case reflect.Int:
		return time.Duration(i.(int)) * time.Second
	case reflect.String:
		i, _ := strconv.Atoi(i.(string))
		return time.Duration(i) * time.Second
	case reflect.Float64:
		return time.Duration(i.(float64)) * time.Second
	default:
		return time.Duration(reflect.ValueOf(i).Int()) * time.Second
	}
}

func (t TlsSettings) EffectiveServerNames() []string {
	if len(t.ServerNames) > 0 {
		return t.ServerNames
	}
	if t.ServerName == "" {
		return nil
	}
	return []string{t.ServerName}
}

func (t TlsSettings) EffectiveShortIds() []string {
	if len(t.ShortIds) > 0 {
		return t.ShortIds
	}
	if t.ShortId == "" {
		return nil
	}
	return []string{t.ShortId}
}

func (t TlsSettings) PrimaryServerName() string {
	serverNames := t.EffectiveServerNames()
	if len(serverNames) == 0 {
		return ""
	}
	return serverNames[0]
}
