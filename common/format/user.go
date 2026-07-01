package format

// UserTag is called on every user/limiter/traffic-counter lookup across all
// protocols (vless/vmess/trojan/shadowsocks/hysteria2/tuic/anytls). Plain
// concatenation avoids fmt.Sprintf's format-string parsing and reflection
// overhead for what is just two strings joined by a separator.
func UserTag(tag string, uuid string) string {
	return tag + "|" + uuid
}
