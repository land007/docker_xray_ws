package main

import (
	"bytes"
	"context" // 仍然需要导入 context 包，因为 pingViaSOCKS 函数中可能用到
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	// 导入 Xray 核心相关的包
	core "github.com/xtls/xray-core/core"
	_ "github.com/xtls/xray-core/main/distro/all" // 导入所有组件
	"golang.org/x/net/proxy"                      // 导入 SOCKS5 代理库
)

// XrayConfig 结构体对应您提供的 JSON 配置
type XrayConfig struct {
	Log       LogConfig      `json:"log"`
	Inbounds  []InboundConfig  `json:"inbounds"`
	Outbounds []OutboundConfig `json:"outbounds"`
	DNS       DNSConfig      `json:"dns"`
	Routing   RoutingConfig  `json:"routing"`
}

type LogConfig struct {
	Loglevel string `json:"loglevel"`
}

type InboundConfig struct {
	Tag      string          `json:"tag"`
	Port     int             `json:"port"`
	Listen   string          `json:"listen"`
	Protocol string          `json:"protocol"`
	Sniffing SniffingConfig  `json:"sniffing"`
	Settings InboundSettings `json:"settings"`
}

type SniffingConfig struct {
	Enabled      bool     `json:"enabled"`
	DestOverride []string `json:"destOverride"`
	RouteOnly    bool   `json:"routeOnly"`
}

type InboundSettings struct {
	Auth             string `json:"auth"`
	Udp              bool   `json:"udp"`
	AllowTransparent bool   `json:"allowTransparent"`
}

type OutboundConfig struct {
	Tag          string           `json:"tag"`
	Protocol     string           `json:"protocol"`
	Settings     OutboundSettings `json:"settings"`
	StreamSettings StreamSettings   `json:"streamSettings"`
	Mux          MuxConfig        `json:"mux"`
}

type OutboundSettings struct {
	Vnext []VnextConfig `json:"vnext"`
}

type VnextConfig struct {
	Address string      `json:"address"`
	Port    int         `json:"port"`
	Users   []UserConfig `json:"users"`
}

type UserConfig struct {
	ID         string `json:"id"`
	Email      string `json:"email"`
	Security   string `json:"security"`
	Encryption string `json:"encryption"`
}

type StreamSettings struct {
	Network   string     `json:"network"`
	WsSettings WsSettings `json:"wsSettings"`
}

type WsSettings struct {
	Path    string            `json:"path"`
	Host    string            `json:"host"`
	Headers map[string]string `json:"headers"`
}

type MuxConfig struct {
	Enabled     bool `json:"enabled"`
	Concurrency int  `json:"concurrency"`
}

type DNSConfig struct {
	Hosts   map[string]string `json:"hosts"`
	Servers []interface{}     `json:"servers"` // 可以是字符串或对象
}

type RoutingConfig struct {
	DomainStrategy string     `json:"domainStrategy"`
	Rules          []RuleConfig `json:"rules"`
}

type RuleConfig struct {
	Type       string   `json:"type"`
	InboundTag []string `json:"inboundTag,omitempty"`
	OutboundTag string   `json:"outboundTag"`
	Port       string   `json:"port,omitempty"`
	Network    string   `json:"network,omitempty"`
	Domain     []string `json:"domain,omitempty"`
	IP         []string `json:"ip,omitempty"`
}

func main() {
	// 您提供的 Xray 配置 (JSON 字符串)
	jsonConfig := `{
        "log": {
            "loglevel": "warning"
        },
        "inbounds": [
            {
                "tag": "socks",
                "port": 20170,
                "listen": "0.0.0.0",
                "protocol": "socks",
                "sniffing": {
                    "enabled": true,
                    "destOverride": [
                        "http",
                        "tls"
                    ],
                    "routeOnly": false
                },
                "settings": {
                    "auth": "noauth",
                    "udp": true,
                    "allowTransparent": false
                }
            }
        ],
        "outbounds": [
            {
                "tag": "proxy",
                "protocol": "vless",
                "settings": {
                    "vnext": [
                        {
                            "address": "104.24.143.159",
                            "port": 80,
                            "users": [
                                {
                                    "id": "18fc00f7-7d69-4873-929a-907209ac5c8a",
                                    "email": "t@t.tt",
                                    "security": "auto",
                                    "encryption": "none"
                                }
                            ]
                        }
                    ]
                },
                "streamSettings": {
                    "network": "ws",
                    "wsSettings": {
                        "path": "/?ed=2560",
                        "host": "silent-credit-f14c.jiayqpad.workers.dev",
                        "headers": {
                            "Host": "silent-credit-f14c.jiayqpad.workers.dev"
                        }
                    }
                },
                "mux": {
                    "enabled": false,
                    "concurrency": -1
                }
            },
            {
                "tag": "direct",
                "protocol": "freedom",
                "streamSettings": {
                    "network": "tcp"
                }
            },
            {
                "tag": "block",
                "protocol": "blackhole",
                "streamSettings": {
                    "network": "tcp"
                }
            }
        ],
        "dns": {
            "hosts": {
                "dns.google": "8.8.8.8",
                "proxy.example.com": "127.0.0.1"
            },
            "servers": [
                {
                    "address": "1.1.1.1",
                    "domains": [
                        "geosite:geolocation-!cn"
                    ],
                    "expectIPs": [
                        "geoip:!cn"
                    ]
                },
                {
                    "address": "223.5.5.5",
                    "domains": [
                        "geosite:cn"
                    ],
                    "expectIPs": [
                        "geoip:cn"
                    ]
                },
                "8.8.8.8",
                "https://dns.google/dns-query"
            ]
        },
        "routing": {
            "domainStrategy": "AsIs",
            "rules": [
                {
                    "type": "field",
                    "inboundTag": [
                        "api"
                    ],
                    "outboundTag": "api"
                },
                {
                    "type": "field",
                    "port": "443",
                    "network": "udp",
                    "outboundTag": "block"
                },
                {
                    "type": "field",
                    "outboundTag": "block",
                    "domain": [
                        "geosite:category-ads-all"
                    ]
                },
                {
                    "type": "field",
                    "outboundTag": "direct",
                    "ip": [
                        "geoip:private"
                    ]
                },
                {
                    "type": "field",
                    "outboundTag": "direct",
                    "domain": [
                        "geosite:private"
                    ]
                },
                {
                    "type": "field",
                    "port": "0-65535",
                    "outboundTag": "proxy"
                }
            ]
        }
    }`

	// 将 JSON 配置解析为 Go 结构体
	var config XrayConfig
	err := json.Unmarshal([]byte(jsonConfig), &config)
	if err != nil {
		fmt.Printf("解析配置失败: %v\n", err)
		return
	}

	// 将 Go 结构体转换回 JSON (为了 Xray 核心 API)
	xrayConfigBytes, err := json.Marshal(config)
	if err != nil {
		fmt.Printf("转换配置为 JSON 失败: %v\n", err)
		return
	}

	// 启动 Xray 核心的正确方式 (两步走)
	configReader := bytes.NewReader(xrayConfigBytes)

	// 1. 加载配置，得到 *core.Config 对象
	xrayConfigObj, err := core.LoadConfig("json", configReader)
	if err != nil {
		fmt.Printf("加载 Xray 配置失败: %v\n", err)
		return
	}

	// 2. 使用配置对象创建 Xray 实例，得到 *core.Instance 对象
	// 注意: 某些 Xray-core 版本 core.New 只接受一个参数 (*core.Config)
	// 根据最新的报错 "too many arguments", 我们移除 context.Background()
	xrayInstance, err := core.New(xrayConfigObj) // <-- 修正后的调用
	if err != nil {
		fmt.Printf("创建 Xray 实例失败: %v\n", err)
		return
	}
	// 启动 Xray 核心的正确方式结束

	// 启动 Xray 路由 (现在 xrayInstance 是 *core.Instance 类型，它有 Start 方法)
	if err := xrayInstance.Start(); err != nil {
		fmt.Printf("Xray 实例启动失败: %v\n", err)
		return
	}
	defer xrayInstance.Close() // Xray 实例现在也有 Close 方法

	fmt.Println("Xray 核心已启动，SOCKS 代理监听在 0.0.0.0:20170")
	time.Sleep(2 * time.Second) // 等待 Xray 完全启动

	proxyAddr := "127.0.0.1:20170"

	// --- Ping 测试 ---
	fmt.Println("\n--- 开始 Ping 测试 (通过 SOCKS 代理) ---")
	targetIP := "8.8.8.8" // Google DNS
	pingCount := 4
	for i := 0; i < pingCount; i++ {
		rtt, err := pingViaSOCKS(proxyAddr, targetIP)
		if err != nil {
			fmt.Printf("Ping %s 失败: %v\n", targetIP, err)
		} else {
			fmt.Printf("从 %s Ping %s: RTT = %d ms\n", proxyAddr, targetIP, rtt.Milliseconds())
		}
		time.Sleep(1 * time.Second)
	}

	// --- 代理速度测试 ---
	fmt.Println("\n--- 开始代理速度测试 (通过 SOCKS 代理) ---")
	testURL := "http://speedtest.tele2.net/1MB.zip" // 一个小文件供下载
	downloadSpeed, err := downloadViaSOCKS(proxyAddr, testURL)
	if err != nil {
		fmt.Printf("代理速度测试失败: %v\n", err)
	} else {
		fmt.Printf("代理下载速度: %.2f Mbps\n", downloadSpeed)
	}

	fmt.Println("\n测试完成。")
}

// pingViaSOCKS 尝试通过 SOCKS 代理连接目标 IP 并模拟 Ping (TCP 连接建立时间)
func pingViaSOCKS(proxyAddr, targetIP string) (time.Duration, error) {
	dialer, err := proxy.SOCKS5("tcp", proxyAddr, nil, proxy.Direct) // 使用 golang.org/x/net/proxy
	if err != nil {
		return 0, fmt.Errorf("创建 SOCKS5 dialer 失败: %w", err)
	}

	start := time.Now()
	conn, err := dialer.Dial("tcp", net.JoinHostPort(targetIP, "80")) // DialContext to Dial for proxy.SOCKS5
	if err != nil {
		return 0, fmt.Errorf("通过 SOCKS 代理连接 %s 失败: %w", targetIP, err)
	}
	defer conn.Close()
	return time.Since(start), nil
}

// downloadViaSOCKS 通过 SOCKS 代理下载文件并计算速度
func downloadViaSOCKS(proxyAddr, downloadURL string) (float64, error) {
	proxyURL, err := url.Parse("socks5://" + proxyAddr)
	if err != nil {
		return 0, fmt.Errorf("解析代理 URL 失败: %w", err)
	}

	// Create a SOCKS5 dialer for the HTTP client's transport
	dialer, err := proxy.SOCKS5("tcp", proxyAddr, nil, proxy.Direct)
	if err != nil {
		return 0, fmt.Errorf("创建 SOCKS5 dialer 失败: %w", err)
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dialer.Dial(network, addr) // Use the SOCKS5 dialer
			},
			TLSHandshakeTimeout: 10 * time.Second,
		},
		Timeout: 60 * time.Second, // 整体请求超时
	}

	req, err := http.NewRequest("GET", downloadURL, nil)
	if err != nil {
		return 0, fmt.Errorf("创建请求失败: %w", err)
	}

	start := time.Now()
	resp, err := httpClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("发起请求失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("下载失败，状态码: %d", resp.StatusCode)
	}

	// 限制读取大小以避免下载整个大文件，如果文件很大的话
	// 假设我们只关心前 1MB 的下载速度
	maxReadBytes := int64(1 * 1024 * 1024) // 1 MB
	n, err := io.CopyN(io.Discard, resp.Body, maxReadBytes)
	if err != nil && err != io.EOF {
		return 0, fmt.Errorf("读取响应体失败: %w", err)
	}

	duration := time.Since(start)
	if duration == 0 {
		return 0, fmt.Errorf("下载时间过短，无法计算速度")
	}

	// 计算速度 (MB/s)
	speedBytesPerSecond := float64(n) / duration.Seconds()
	// 转换为 Mbps (兆比特每秒)
	speedMbps := (speedBytesPerSecond * 8) / (1024 * 1024)
	return speedMbps, nil
}

// newSocks5Dialer 创建一个 net.Dialer，通过 SOCKS5 代理进行连接
func newSocks5Dialer(proxyAddr string) (*net.Dialer, error) {
	return nil, fmt.Errorf("newSocks5Dialer is deprecated, use proxy.SOCKS5 directly")
}