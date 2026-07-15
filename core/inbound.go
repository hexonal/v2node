package core

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	panel "github.com/wyx2685/v2node/api/v2board"
	vconf "github.com/wyx2685/v2node/conf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/inbound"
	"github.com/xtls/xray-core/infra/conf"
	coreConf "github.com/xtls/xray-core/infra/conf"
)

type NetworkSettingsProxyProtocol struct {
	AcceptProxyProtocol bool `json:"acceptProxyProtocol"`
}

func (v *V2Core) removeInbound(tag string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return v.ihm.RemoveHandler(ctx, tag)
}

func (v *V2Core) addInbound(config *core.InboundHandlerConfig) error {
	rawHandler, err := core.CreateObject(v.Server, config)
	if err != nil {
		return err
	}
	handler, ok := rawHandler.(inbound.Handler)
	if !ok {
		return fmt.Errorf("not an InboundHandler: %s", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := v.ihm.AddHandler(ctx, handler); err != nil {
		return err
	}
	return nil
}

// BuildInbound build Inbound config for different protocol
func buildInbound(nodeInfo *panel.NodeInfo, tag string, nodeCfg *vconf.NodeConfig) (*core.InboundHandlerConfig, error) {
	if nodeCfg == nil {
		nodeCfg = &vconf.NodeConfig{}
	}
	in := &coreConf.InboundDetourConfig{}
	var err error
	switch nodeInfo.Type {
	case "vless":
		err = buildVLess(nodeInfo, in)
	case "vmess":
		err = buildVMess(nodeInfo, in)
	case "trojan":
		err = buildTrojan(nodeInfo, in)
	case "shadowsocks":
		err = buildShadowsocks(nodeInfo, in)
	case "hysteria2":
		err = buildHysteria2(nodeInfo, in)
	case "tuic":
		err = buildTuic(nodeInfo, in)
	case "anytls":
		err = buildAnyTLS(nodeInfo, in)
	default:
		return nil, fmt.Errorf("unsupported node type: %s", nodeInfo.Type)
	}
	if err != nil {
		return nil, err
	}
	// Set network protocol
	if len(nodeInfo.Common.NetworkSettings) > 0 {
		n := &NetworkSettingsProxyProtocol{}
		err := json.Unmarshal(nodeInfo.Common.NetworkSettings, n)
		if err != nil {
			return nil, fmt.Errorf("unmarshal network settings error: %s", err)
		}
		if n.AcceptProxyProtocol {
			if in.StreamSetting == nil {
				t := coreConf.TransportProtocol(nodeInfo.Common.Network)
				in.StreamSetting = &coreConf.StreamConfig{
					Network: &t,
					SocketSettings: &coreConf.SocketConfig{
						AcceptProxyProtocol: n.AcceptProxyProtocol,
					},
				}
			} else {
				in.StreamSetting.SocketSettings = &coreConf.SocketConfig{
					AcceptProxyProtocol: n.AcceptProxyProtocol,
				}
			}
		}
	}
	// Set socket settings for trusted X-Forwarded-For headers
	if len(nodeInfo.Common.TrustedXForwardedFor) > 0 {
		if in.StreamSetting == nil {
			return nil, errors.New("stream settings must be configured to set trusted X-Forwarded-For headers")
		}
		if in.StreamSetting.SocketSettings == nil {
			in.StreamSetting.SocketSettings = &coreConf.SocketConfig{}
		}
		in.StreamSetting.SocketSettings.TrustedXForwardedFor = nodeInfo.Common.TrustedXForwardedFor
	}

	// Set server port
	in.PortList = &coreConf.PortList{
		Range: []coreConf.PortRange{
			{
				From: uint32(nodeInfo.Common.ServerPort),
				To:   uint32(nodeInfo.Common.ServerPort),
			}},
	}
	// Set Listen IP address
	ipAddress := net.ParseAddress(nodeInfo.Common.ListenIP)
	in.ListenOn = &coreConf.Address{Address: ipAddress}
	// Set SniffingConfig (per-node configurable; nil Sniffing keeps the old
	// hardcoded default of enabled + http/tls/quic). Enabled=false leaves
	// in.SniffingConfig nil so xray does no sniffing at all.
	sn := nodeCfg.Sniffing
	if sn.ResolvedEnabled() {
		in.SniffingConfig = &coreConf.SniffingConfig{
			Enabled:      true,
			DestOverride: coreConf.StringList(sn.ResolvedDestOverride()),
			MetadataOnly: sn.ResolvedMetadataOnly(),
			RouteOnly:    sn.ResolvedRouteOnly(),
		}
	}

	// Set TLS or Reality settings
	switch nodeInfo.Security {
	case panel.Tls:
		if nodeInfo.Common.CertInfo == nil {
			return nil, errors.New("the CertInfo is not vail")
		}
		switch nodeInfo.Common.CertInfo.CertMode {
		case "none", "":
			break
		default:
			if in.StreamSetting == nil {
				in.StreamSetting = &coreConf.StreamConfig{}
			}
			in.StreamSetting.Security = "tls"
			in.StreamSetting.TLSSettings = &coreConf.TLSConfig{
				Certs: []*coreConf.TLSCertConfig{
					{
						CertFile:     nodeInfo.Common.CertInfo.CertFile,
						KeyFile:      nodeInfo.Common.CertInfo.KeyFile,
						OcspStapling: 3600,
					},
				},
				RejectUnknownSNI: nodeInfo.Common.CertInfo.RejectUnknownSni,
			}
			if nodeInfo.Type == "hysteria2" || nodeInfo.Type == "tuic" {
				alpnList := &coreConf.StringList{"h3"}
				in.StreamSetting.TLSSettings.ALPN = alpnList
			}
		}
	case panel.Reality:
		if in.StreamSetting == nil {
			in.StreamSetting = &coreConf.StreamConfig{}
		}
		in.StreamSetting.Security = "reality"
		v := nodeInfo.Common
		serverNames := v.TlsSettings.EffectiveServerNames()
		shortIds := v.TlsSettings.EffectiveShortIds()
		dest := v.TlsSettings.Dest
		if dest == "" {
			dest = v.TlsSettings.PrimaryServerName()
		}
		xver := v.TlsSettings.Xver
		d, err := json.Marshal(fmt.Sprintf(
			"%s:%s",
			dest,
			v.TlsSettings.ServerPort))
		if err != nil {
			return nil, fmt.Errorf("marshal reality dest error: %s", err)
		}
		in.StreamSetting.REALITYSettings = &coreConf.REALITYConfig{
			Dest:         d,
			Xver:         xver,
			Show:         false,
			ServerNames:  serverNames,
			PrivateKey:   v.TlsSettings.PrivateKey,
			MinClientVer: "0.0.1",
			ShortIds:     shortIds,
			Mldsa65Seed:  v.TlsSettings.Mldsa65Seed,
		}
	default:
		break
	}
	// Wire XMC (finalmask.tcp) — a TCP-only mask that wraps the raw listener
	// before TLS/REALITY negotiate. Two independent opt-in gates before it
	// ever touches a live listener: the panel must set finalmask_tcp=xmc AND
	// this node's local config.json must set AllowFinalMaskTcp=true. Neither
	// alone is enough — this is a brand-new, ecosystem-unproven transport
	// (no mainstream client ships support yet as of 2026-07) and it must
	// not be possible to flip on with a single fat-fingered panel edit.
	//
	// History: an earlier version of this block hard-rejected
	// security=reality here, because a live local repro
	// (vless+reality+finalmask.tcp:xmc) panicked the whole xray-core process
	// on the first connection ("interface conversion: *xmc.serverConn is not
	// reality.CloseWriteConn: missing method CloseWrite" — REALITY's server
	// side hard type-asserts the wrapped conn for its splice-to-real-website
	// fallback path). Root-caused and fixed upstream in our own xray-core
	// fork (hexonal/Xray-core, tag v1.260711.2): added CloseWrite() to
	// xmc.serverConn, forwarding to the underlying raw conn — safe because
	// half-close is a socket-level operation below XMC's byte-stream cipher.
	// Re-verified with the same local repro post-fix: REALITY handshake
	// completes for real (isHandshakeComplete=true), VLESS+Vision proxies
	// correctly to the actual requested destination (not REALITY's disguise
	// fallback), no panic. The REALITY-specific guard is no longer needed.
	//
	// Upstream position (our PR XTLS/Xray-core#6497 fixing this exact crash
	// was closed by the maintainers, quoting RPRX: REALITY should not be
	// combined with any TCP Finalmask at all — pointless, since REALITY's
	// own TLS mimicry already covers what Finalmask would add; cert-free
	// strong encryption should use VLESS Encryption (mlkem768x25519plus)
	// instead). So this code path is intentionally "won't crash if someone
	// configures it anyway", not something we should actively recommend or
	// enable in production — the two-gate design above already keeps it
	// off by default; don't build UI/docs steering operators toward turning
	// it on for a REALITY node.
	if nodeCfg.AllowFinalMaskTcp && nodeInfo.Common.FinalMaskTcp == "xmc" {
		switch nodeInfo.Type {
		case "vless", "vmess", "trojan", "anytls":
			if nodeInfo.Common.Network != "tcp" {
				log.Warnf("node %d: finalmask_tcp=xmc requires network=tcp, got %q; ignoring", nodeInfo.Id, nodeInfo.Common.Network)
				break
			}
			xs := nodeInfo.Common.FinalMaskTcpSettings
			if xs.Password == "" {
				// xray-core's XMC.Build() hard-errors on an empty password
				// anyway; fail the whole inbound build loudly here instead
				// of letting it fail deeper with a less obvious message.
				return nil, fmt.Errorf("node %d: finalmask_tcp=xmc requires a non-empty password", nodeInfo.Id)
			}
			raw, err := json.Marshal(xs)
			if err != nil {
				return nil, fmt.Errorf("marshal xmc settings error: %s", err)
			}
			rawMsg := json.RawMessage(raw)
			if in.StreamSetting == nil {
				t := coreConf.TransportProtocol("tcp")
				in.StreamSetting = &coreConf.StreamConfig{Network: &t}
			}
			if in.StreamSetting.FinalMask == nil {
				in.StreamSetting.FinalMask = &coreConf.FinalMask{}
			}
			in.StreamSetting.FinalMask.Tcp = append(in.StreamSetting.FinalMask.Tcp, coreConf.Mask{
				Type:     "xmc",
				Settings: &rawMsg,
			})
		default:
			log.Warnf("node %d: finalmask_tcp=xmc is only wired for vless/vmess/trojan/anytls over tcp; protocol=%s ignored", nodeInfo.Id, nodeInfo.Type)
		}
	}
	// Server-side TCP_FASTOPEN is opt-in per node via inboundTFO (default
	// false). On the currently deployed nodes' kernel, setsockopt(
	// TCP_FASTOPEN, 256) returns ENOPROTOOPT ("protocol not available") —
	// confirmed via live logs, not a config mistake, likely a cloud-kernel
	// restriction on this specific sockopt even with net.ipv4.tcp_fastopen=3
	// set and visible in-container. Non-fatal (connection still completes
	// without TFO) but pure log noise with no benefit there, hence default
	// off — kept configurable since a different host/kernel may support it.
	// Client-side TCP_FASTOPEN_CONNECT in outbound.go is unaffected and
	// confirmed working regardless of this setting.
	inboundTFO := nodeCfg.InboundTFO
	sock := nodeCfg.Sockopt
	if inboundTFO || sock.HasAny() {
		if in.StreamSetting == nil {
			in.StreamSetting = &coreConf.StreamConfig{}
		}
		if in.StreamSetting.SocketSettings == nil {
			in.StreamSetting.SocketSettings = &coreConf.SocketConfig{}
		}
		ss := in.StreamSetting.SocketSettings
		if inboundTFO {
			ss.TFO = true
		}
		// Only touch these fields when the operator set any sockopt, so the
		// no-config path attaches nothing extra and reuses whatever
		// SocketSettings AcceptProxyProtocol may have created above.
		if sock.HasAny() {
			ss.TCPKeepAliveIdle = sock.ResolvedKeepAliveIdle()
			ss.TCPKeepAliveInterval = sock.ResolvedKeepAliveInterval()
			ss.TCPUserTimeout = sock.ResolvedUserTimeout()
			ss.TCPCongestion = sock.ResolvedCongestion()
			ss.TcpMptcp = sock.ResolvedMptcp()
		}
	}
	in.Tag = tag
	return in.Build()
}

func buildVLess(nodeInfo *panel.NodeInfo, inbound *coreConf.InboundDetourConfig) error {
	v := nodeInfo.Common
	inbound.Protocol = "vless"
	var err error
	decryption := "none"
	if nodeInfo.Common.Encryption != "" {
		switch nodeInfo.Common.Encryption {
		case "mlkem768x25519plus":
			encSettings := nodeInfo.Common.EncryptionSettings
			parts := []string{
				"mlkem768x25519plus",
				encSettings.Mode,
				encSettings.Ticket,
			}
			if encSettings.ServerPadding != "" {
				parts = append(parts, encSettings.ServerPadding)
			}
			parts = append(parts, encSettings.PrivateKey)
			decryption = strings.Join(parts, ".")
		default:
			return fmt.Errorf("vless decryption method %s is not support", nodeInfo.Common.Encryption)
		}
	}
	s, err := json.Marshal(&coreConf.VLessInboundConfig{
		Decryption: decryption,
	})
	if err != nil {
		return fmt.Errorf("marshal vless config error: %s", err)
	}
	inbound.Settings = (*json.RawMessage)(&s)
	if len(v.NetworkSettings) == 0 {
		return nil
	}
	t := coreConf.TransportProtocol(v.Network)
	inbound.StreamSetting = &coreConf.StreamConfig{Network: &t}
	switch v.Network {
	case "tcp":
		err := json.Unmarshal(v.NetworkSettings, &inbound.StreamSetting.TCPSettings)
		if err != nil {
			return fmt.Errorf("unmarshal tcp settings error: %s", err)
		}
	case "ws":
		err := json.Unmarshal(v.NetworkSettings, &inbound.StreamSetting.WSSettings)
		if err != nil {
			return fmt.Errorf("unmarshal ws settings error: %s", err)
		}
	case "grpc":
		err := json.Unmarshal(v.NetworkSettings, &inbound.StreamSetting.GRPCSettings)
		if err != nil {
			return fmt.Errorf("unmarshal grpc settings error: %s", err)
		}
	case "httpupgrade":
		err := json.Unmarshal(v.NetworkSettings, &inbound.StreamSetting.HTTPUPGRADESettings)
		if err != nil {
			return fmt.Errorf("unmarshal httpupgrade settings error: %s", err)
		}
	case "splithttp", "xhttp":
		err := json.Unmarshal(v.NetworkSettings, &inbound.StreamSetting.SplitHTTPSettings)
		if err != nil {
			return fmt.Errorf("unmarshal xhttp settings error: %s", err)
		}
	default:
		return errors.New("the network type is not vail")
	}
	return nil
}

func buildVMess(nodeInfo *panel.NodeInfo, inbound *coreConf.InboundDetourConfig) error {
	v := nodeInfo.Common
	// Set vmess
	inbound.Protocol = "vmess"
	var err error
	s, err := json.Marshal(&coreConf.VMessInboundConfig{})
	if err != nil {
		return fmt.Errorf("marshal vmess settings error: %s", err)
	}
	inbound.Settings = (*json.RawMessage)(&s)
	if len(v.NetworkSettings) == 0 {
		return nil
	}
	t := coreConf.TransportProtocol(v.Network)
	inbound.StreamSetting = &coreConf.StreamConfig{Network: &t}
	switch v.Network {
	case "tcp":
		err := json.Unmarshal(v.NetworkSettings, &inbound.StreamSetting.TCPSettings)
		if err != nil {
			return fmt.Errorf("unmarshal tcp settings error: %s", err)
		}
	case "ws":
		err := json.Unmarshal(v.NetworkSettings, &inbound.StreamSetting.WSSettings)
		if err != nil {
			return fmt.Errorf("unmarshal ws settings error: %s", err)
		}
	case "grpc":
		err := json.Unmarshal(v.NetworkSettings, &inbound.StreamSetting.GRPCSettings)
		if err != nil {
			return fmt.Errorf("unmarshal grpc settings error: %s", err)
		}
	case "httpupgrade":
		err := json.Unmarshal(v.NetworkSettings, &inbound.StreamSetting.HTTPUPGRADESettings)
		if err != nil {
			return fmt.Errorf("unmarshal httpupgrade settings error: %s", err)
		}
	case "splithttp", "xhttp":
		err := json.Unmarshal(v.NetworkSettings, &inbound.StreamSetting.SplitHTTPSettings)
		if err != nil {
			return fmt.Errorf("unmarshal xhttp settings error: %s", err)
		}
	default:
		return errors.New("the network type is not vail")
	}
	return nil
}

func buildTrojan(nodeInfo *panel.NodeInfo, inbound *coreConf.InboundDetourConfig) error {
	inbound.Protocol = "trojan"
	v := nodeInfo.Common
	s, err := json.Marshal(&coreConf.TrojanServerConfig{})
	if err != nil {
		return fmt.Errorf("marshal trojan settings error: %s", err)
	}
	inbound.Settings = (*json.RawMessage)(&s)
	network := v.Network
	if network == "" {
		network = "tcp"
	}
	t := coreConf.TransportProtocol(network)
	inbound.StreamSetting = &coreConf.StreamConfig{Network: &t}
	if len(v.NetworkSettings) == 0 {
		return nil
	}
	switch network {
	case "tcp":
		err := json.Unmarshal(v.NetworkSettings, &inbound.StreamSetting.TCPSettings)
		if err != nil {
			return fmt.Errorf("unmarshal tcp settings error: %s", err)
		}
	case "ws":
		err := json.Unmarshal(v.NetworkSettings, &inbound.StreamSetting.WSSettings)
		if err != nil {
			return fmt.Errorf("unmarshal ws settings error: %s", err)
		}
	case "grpc":
		err := json.Unmarshal(v.NetworkSettings, &inbound.StreamSetting.GRPCSettings)
		if err != nil {
			return fmt.Errorf("unmarshal grpc settings error: %s", err)
		}
	case "httpupgrade":
		err := json.Unmarshal(v.NetworkSettings, &inbound.StreamSetting.HTTPUPGRADESettings)
		if err != nil {
			return fmt.Errorf("unmarshal httpupgrade settings error: %s", err)
		}
	case "splithttp", "xhttp":
		err := json.Unmarshal(v.NetworkSettings, &inbound.StreamSetting.SplitHTTPSettings)
		if err != nil {
			return fmt.Errorf("unmarshal xhttp settings error: %s", err)
		}
	default:
		return errors.New("the network type is not vail")
	}
	return nil
}

type ShadowsocksHTTPNetworkSettings struct {
	AcceptProxyProtocol bool   `json:"acceptProxyProtocol"`
	Path                string `json:"path"`
	Host                string `json:"Host"`
}

func buildShadowsocks(nodeInfo *panel.NodeInfo, inbound *coreConf.InboundDetourConfig) error {
	inbound.Protocol = "shadowsocks"
	s := nodeInfo.Common
	settings := &coreConf.ShadowsocksServerConfig{
		Cipher: s.Cipher,
	}
	p := make([]byte, 32)
	_, err := rand.Read(p)
	if err != nil {
		return fmt.Errorf("generate random password error: %s", err)
	}
	randomPasswd := hex.EncodeToString(p)
	cipher := s.Cipher
	if s.ServerKey != "" {
		settings.Password = s.ServerKey
		randomPasswd = base64.StdEncoding.EncodeToString([]byte(randomPasswd))
		cipher = ""
	}
	defaultSSuser := &coreConf.ShadowsocksUserConfig{
		Cipher:   cipher,
		Password: randomPasswd,
	}
	settings.Users = append(settings.Users, defaultSSuser)
	// Default: support both tcp and udp
	settings.NetworkList = &coreConf.NetworkList{"tcp", "udp"}
	// Only set StreamSetting when NetworkSettings is configured
	if len(s.NetworkSettings) != 0 {
		shttp := &ShadowsocksHTTPNetworkSettings{}
		err := json.Unmarshal(s.NetworkSettings, shttp)
		if err != nil {
			return fmt.Errorf("unmarshal shadowsocks settings error: %s", err)
		}
		// HTTP obfuscation requires TCP only (PROXY protocol can work with UDP)
		if shttp.Path != "" || shttp.Host != "" {
			// Restrict protocol-level network list to TCP only for HTTP obfuscation
			settings.NetworkList = &coreConf.NetworkList{"tcp"}
		}

		// Set StreamSetting for TCP features (PROXY protocol and/or HTTP obfuscation)
		if shttp.AcceptProxyProtocol || shttp.Path != "" || shttp.Host != "" {
			t := coreConf.TransportProtocol("tcp")
			inbound.StreamSetting = &coreConf.StreamConfig{Network: &t}
			inbound.StreamSetting.TCPSettings = &coreConf.TCPConfig{}
			inbound.StreamSetting.TCPSettings.AcceptProxyProtocol = shttp.AcceptProxyProtocol
			// Set HTTP header settings if path or host is configured
			if shttp.Path != "" || shttp.Host != "" {
				httpHeader := map[string]interface{}{
					"type":    "http",
					"request": map[string]interface{}{},
				}
				request := httpHeader["request"].(map[string]interface{})
				// Use "/" as default path if not specified
				path := shttp.Path
				if path == "" {
					path = "/"
				}
				request["path"] = []string{path}
				if shttp.Host != "" {
					request["headers"] = map[string]interface{}{
						"Host": []string{shttp.Host},
					}
				}
				headerJSON, err := json.Marshal(httpHeader)
				if err == nil {
					inbound.StreamSetting.TCPSettings.HeaderConfig = json.RawMessage(headerJSON)
				}
			}
		}
	}

	sets, err := json.Marshal(settings)
	inbound.Settings = (*json.RawMessage)(&sets)
	if err != nil {
		return fmt.Errorf("marshal shadowsocks settings error: %s", err)
	}
	return nil
}

func buildHysteria2(nodeInfo *panel.NodeInfo, inbound *coreConf.InboundDetourConfig) error {
	inbound.Protocol = "hysteria"
	s := nodeInfo.Common
	settings := &coreConf.HysteriaServerConfig{
		Version: 2,
	}

	t := coreConf.TransportProtocol("hysteria")
	up := conf.Bandwidth(strconv.Itoa(s.UpMbps) + "mbps")
	down := conf.Bandwidth(strconv.Itoa(s.DownMbps) + "mbps")
	inbound.StreamSetting = &coreConf.StreamConfig{Network: &t}
	hysteriasetting := &coreConf.HysteriaConfig{
		Version: 2,
	}
	finalmask := &coreConf.FinalMask{}
	// Ignore_Client_Bandwidth's own name states the intent: true means
	// force the panel-configured Up/Down regardless of what the client
	// reports ("force-brutal": constant-rate sender, no real congestion
	// backoff — self-congesting if the configured rate exceeds the actual
	// path's capacity). false means respect the client's reported rate,
	// i.e. plain "brutal", which takes min(configured, client-reported).
	// The condition used to be inverted from this (`!s.Ignore_Client_Bandwidth`
	// gated the force-brutal branch, and Ignore_Client_Bandwidth=true fell
	// through to no QuicParams at all / plain BBR) — backwards relative to
	// what the field name promises.
	if s.UpMbps > 0 || s.DownMbps > 0 {
		congestion := "brutal"
		if s.Ignore_Client_Bandwidth {
			congestion = "force-brutal"
		}
		finalmask.QuicParams = &coreConf.QuicParamsConfig{
			Congestion: congestion,
			BrutalUp:   up,
			BrutalDown: down,
		}
	}
	if s.Obfs != "" && s.ObfsPassword != "" {
		rawobfsJSON := json.RawMessage(fmt.Sprintf(`{"password":"%s"}`, s.ObfsPassword))
		finalmask.Udp = []conf.Mask{
			{
				Type:     s.Obfs,
				Settings: &rawobfsJSON,
			},
		}
	}
	inbound.StreamSetting.FinalMask = finalmask
	sets, err := json.Marshal(settings)
	inbound.Settings = (*json.RawMessage)(&sets)
	inbound.StreamSetting.HysteriaSettings = hysteriasetting
	if err != nil {
		return fmt.Errorf("marshal hysteria2 settings error: %s", err)
	}
	return nil
}

func buildTuic(nodeInfo *panel.NodeInfo, inbound *coreConf.InboundDetourConfig) error {
	inbound.Protocol = "tuic"
	s := nodeInfo.Common
	// transport/internet/tuic/service.go only special-cases the literal
	// string "bbr"; "cubic"/"new_reno"/anything else (including "") falls
	// through to quic-go's built-in Cubic sender. Leaving this blank when
	// the panel doesn't set it means tuic silently ends up on Cubic while
	// hysteria2 (elsewhere in this file) defaults to BBR when unconfigured
	// — inconsistent with each other, and Cubic is loss-based, which on the
	// cross-border/high-latency links documented for this deployment tends
	// to misread ordinary jitter-induced loss as congestion and needlessly
	// shrink its window (the same reasoning behind standardizing on BBR
	// everywhere else in this project). Default to "bbr" so an unset panel
	// value gets the same congestion control as the hysteria2 default.
	congestionControl := s.CongestionControl
	if congestionControl == "" {
		congestionControl = "bbr"
	}
	settings := &coreConf.TuicServerConfig{
		CongestionControl: congestionControl,
		ZeroRttHandshake:  s.ZeroRTTHandshake,
	}
	t := coreConf.TransportProtocol("tuic")
	inbound.StreamSetting = &coreConf.StreamConfig{Network: &t}
	sets, err := json.Marshal(settings)
	inbound.Settings = (*json.RawMessage)(&sets)
	if err != nil {
		return fmt.Errorf("marshal tuic settings error: %s", err)
	}
	return nil
}

func buildAnyTLS(nodeInfo *panel.NodeInfo, inbound *coreConf.InboundDetourConfig) error {
	inbound.Protocol = "anytls"
	v := nodeInfo.Common
	settings := &coreConf.AnyTLSServerConfig{
		PaddingScheme: v.PaddingScheme,
	}
	t := coreConf.TransportProtocol(v.Network)
	inbound.StreamSetting = &coreConf.StreamConfig{Network: &t}
	if len(v.NetworkSettings) != 0 {
		switch v.Network {
		case "tcp":
			err := json.Unmarshal(v.NetworkSettings, &inbound.StreamSetting.TCPSettings)
			if err != nil {
				return fmt.Errorf("unmarshal tcp settings error: %s", err)
			}
		case "ws":
			err := json.Unmarshal(v.NetworkSettings, &inbound.StreamSetting.WSSettings)
			if err != nil {
				return fmt.Errorf("unmarshal ws settings error: %s", err)
			}
		case "grpc":
			err := json.Unmarshal(v.NetworkSettings, &inbound.StreamSetting.GRPCSettings)
			if err != nil {
				return fmt.Errorf("unmarshal grpc settings error: %s", err)
			}
		case "httpupgrade":
			err := json.Unmarshal(v.NetworkSettings, &inbound.StreamSetting.HTTPUPGRADESettings)
			if err != nil {
				return fmt.Errorf("unmarshal httpupgrade settings error: %s", err)
			}
		case "splithttp", "xhttp":
			err := json.Unmarshal(v.NetworkSettings, &inbound.StreamSetting.SplitHTTPSettings)
			if err != nil {
				return fmt.Errorf("unmarshal xhttp settings error: %s", err)
			}
		default:
			return errors.New("the network type is not vail")
		}
	}
	sets, err := json.Marshal(settings)
	inbound.Settings = (*json.RawMessage)(&sets)
	if err != nil {
		return fmt.Errorf("marshal anytls settings error: %s", err)
	}
	return nil
}
