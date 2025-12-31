// Package tunnel - 路由管理模块
package tunnel

import (
	"fmt"
	"log/slog"
	"net"
	"os/exec"
	"runtime"
	"strings"
)

// RouteManager 路由管理器
type RouteManager struct {
	logger      *slog.Logger
	serverIP    string
	gateway     string
	tunGateway  string
	tunDevice   string // 实际的 TUN 设备名称
	routesAdded []string
	configured  bool
}

// NewRouteManager 创建路由管理器
func NewRouteManager(serverAddr string, tunGateway string, tunDevice string, logger *slog.Logger) *RouteManager {
	// 从服务器地址提取 IP
	host, _, err := net.SplitHostPort(serverAddr)
	if err != nil {
		host = serverAddr
	}

	return &RouteManager{
		logger:     logger,
		serverIP:   host,
		tunGateway: tunGateway,
		tunDevice:  tunDevice,
	}
}

// Setup 配置路由（将所有流量导向 VPN）
func (r *RouteManager) Setup() error {
	r.logger.Info("Setting up VPN routes", "server", r.serverIP, "tunGateway", r.tunGateway)

	switch runtime.GOOS {
	case "darwin":
		return r.setupDarwin()
	case "linux":
		return r.setupLinux()
	case "windows":
		return r.setupWindows()
	default:
		r.logger.Warn("Automatic route configuration not supported on this platform")
		return nil
	}
}

// Cleanup 恢复原始路由
func (r *RouteManager) Cleanup() error {
	if !r.configured {
		return nil
	}

	r.logger.Info("Restoring original routes")

	switch runtime.GOOS {
	case "darwin":
		return r.cleanupDarwin()
	case "linux":
		return r.cleanupLinux()
	case "windows":
		return r.cleanupWindows()
	default:
		return nil
	}
}

// setupDarwin macOS 路由配置
func (r *RouteManager) setupDarwin() error {
	// 1. 获取当前默认网关
	gateway, err := r.getDefaultGatewayDarwin()
	if err != nil {
		return fmt.Errorf("failed to get default gateway: %w", err)
	}
	r.gateway = gateway
	r.logger.Debug("Current default gateway", "gateway", gateway)

	// 2. 添加到服务器的直接路由（确保 Hysteria 连接不走 VPN）
	r.logger.Debug("Adding direct route to server", "server", r.serverIP, "gateway", gateway)
	if err := r.runCmd("route", "add", "-host", r.serverIP, gateway); err != nil {
		r.logger.Warn("Failed to add server route (may already exist)", "error", err)
	} else {
		r.routesAdded = append(r.routesAdded, r.serverIP)
	}

	// 3. 删除默认路由
	r.logger.Debug("Removing default route")
	if err := r.runCmd("route", "delete", "default"); err != nil {
		return fmt.Errorf("failed to delete default route: %w", err)
	}

	// 4. 通过分裂路由添加0.0.0.0/1和128.0.0.0/1（比默认路由更具体，不会被覆盖）
	// 这样做比删除默认路由更安全
	r.logger.Debug("Adding VPN routes (IPv4)")
	if err := r.runCmd("route", "add", "-net", "0.0.0.0/1", r.tunGateway); err != nil {
		return fmt.Errorf("failed to add route 0.0.0.0/1: %w", err)
	}
	if err := r.runCmd("route", "add", "-net", "128.0.0.0/1", r.tunGateway); err != nil {
		return fmt.Errorf("failed to add route 128.0.0.0/1: %w", err)
	}

	// 5. 添加 IPv6 路由（::/1 和 8000::/1）
	if r.tunDevice != "" {
		r.logger.Debug("Adding VPN routes (IPv6)", "device", r.tunDevice)
		// 使用 -inet6 参数添加 IPv6 路由
		if err := r.runCmd("route", "add", "-inet6", "::/1", "-interface", r.tunDevice); err != nil {
			r.logger.Warn("Failed to add IPv6 route ::/1", "error", err)
		}
		if err := r.runCmd("route", "add", "-inet6", "8000::/1", "-interface", r.tunDevice); err != nil {
			r.logger.Warn("Failed to add IPv6 route 8000::/1", "error", err)
		}
	}

	r.configured = true
	r.logger.Info("VPN routes configured successfully")
	return nil
}

// cleanupDarwin macOS 路由恢复
func (r *RouteManager) cleanupDarwin() error {
	var errs []error

	// 1. 删除 VPN 路由 (IPv4)
	r.logger.Debug("Removing VPN routes")
	if err := r.runCmd("route", "delete", "-net", "0.0.0.0/1"); err != nil {
		errs = append(errs, err)
	}
	if err := r.runCmd("route", "delete", "-net", "128.0.0.0/1"); err != nil {
		errs = append(errs, err)
	}

	// 删除 IPv6 路由
	r.runCmd("route", "delete", "-inet6", "::/1")
	r.runCmd("route", "delete", "-inet6", "8000::/1")

	// 2. 恢复默认路由
	if r.gateway != "" {
		r.logger.Debug("Restoring default route", "gateway", r.gateway)
		if err := r.runCmd("route", "add", "default", r.gateway); err != nil {
			errs = append(errs, err)
		}
	}

	// 3. 删除服务器直接路由
	for _, route := range r.routesAdded {
		r.logger.Debug("Removing server route", "route", route)
		if err := r.runCmd("route", "delete", "-host", route); err != nil {
			errs = append(errs, err)
		}
	}

	r.configured = false
	r.routesAdded = nil

	if len(errs) > 0 {
		r.logger.Warn("Some routes could not be removed", "errors", errs)
	} else {
		r.logger.Info("Original routes restored")
	}

	return nil
}

// getDefaultGatewayDarwin 获取 macOS 默认网关
func (r *RouteManager) getDefaultGatewayDarwin() (string, error) {
	cmd := exec.Command("netstat", "-rn")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "default" {
			return fields[1], nil
		}
	}

	return "", fmt.Errorf("default gateway not found")
}

// setupLinux Linux 路由配置 (FwMark 模式)
func (r *RouteManager) setupLinux() error {
	// 1. 获取当前默认网关
	gateway, err := r.getDefaultGatewayLinux()
	if err != nil {
		return fmt.Errorf("failed to get default gateway: %w", err)
	}
	r.logger.Debug("Current default gateway", "gateway", gateway)

	// 添加到服务器的直接路由 (Main 表)
	// 这是必须的，否则由 Hysteria 发出的 UDP 包会被 FwMark 规则路由进 VPN 隧道，导致死循环
	r.logger.Debug("Adding direct route to server", "server", r.serverIP)
	if err := r.runCmd("ip", "route", "add", r.serverIP, "via", gateway); err != nil {
		r.logger.Warn("Failed to add server route (may already exist)", "error", err)
	} else {
		r.routesAdded = append(r.routesAdded, r.serverIP)
	}

	// 2. 添加路由到 table 51820
	r.logger.Debug("Adding routes to table 51820")
	// 添加 VPN 默认路由到表 51820
	if err := r.runCmd("ip", "route", "add", "default", "dev", r.tunDevice, "table", "51820"); err != nil {
		return fmt.Errorf("failed to add default route to table 51820: %w", err)
	}
	r.routesAdded = append(r.routesAdded, "default-51820") // 标记以便清理

	// 3. 添加策略路由规则
	r.logger.Debug("Adding policy routing rules")

	// 规则 1: 查找 main 表，但忽略默认路由 (为了让本地子网流量直连)
	// ip rule add lookup main suppress_prefixlength 0 priority 32764
	if err := r.runCmd("ip", "rule", "add", "lookup", "main", "suppress_prefixlength", "0", "priority", "32764"); err != nil {
		r.logger.Warn("Failed to add suppress_prefixlength rule", "error", err)
	}

	// 规则 2: 所有未标记(非VPN自身)流量查 51820 表
	// ip rule add not fwmark 51820 lookup 51820 priority 32765
	if err := r.runCmd("ip", "rule", "add", "not", "fwmark", "51820", "lookup", "51820", "priority", "32765"); err != nil {
		return fmt.Errorf("failed to add fwmark rule: %w", err)
	}

	// 4. 添加 IPv6 路由 (如果启用)
	if r.tunDevice != "" {
		// IPv6 同样逻辑
		r.runCmd("ip", "-6", "route", "add", "default", "dev", r.tunDevice, "table", "51820")
		r.runCmd("ip", "-6", "rule", "add", "lookup", "main", "suppress_prefixlength", "0", "priority", "32764")
		r.runCmd("ip", "-6", "rule", "add", "not", "fwmark", "51820", "lookup", "51820", "priority", "32765")
	}

	r.configured = true
	r.logger.Info("VPN routes configured successfully (FwMark mode)")
	return nil
}

// cleanupLinux Linux 路由清理 (FwMark 模式)
func (r *RouteManager) cleanupLinux() error {
	r.logger.Info("Cleaning up VPN routes (FwMark mode)")

	// 1. 清理添加到 Main 表的显式路由 (服务器路由)
	for _, route := range r.routesAdded {
		if route != "default-51820" {
			r.runCmd("ip", "route", "del", route)
		}
	}

	// 2. 删除策略路由规则
	// 顺序反向删除
	// ip rule del not fwmark 51820 lookup 51820
	r.runCmd("ip", "rule", "del", "not", "fwmark", "51820", "lookup", "51820")
	// ip rule del lookup main suppress_prefixlength 0
	r.runCmd("ip", "rule", "del", "lookup", "main", "suppress_prefixlength", "0")

	// IPv6 规则清理
	if r.tunDevice != "" {
		r.runCmd("ip", "-6", "rule", "del", "not", "fwmark", "51820", "lookup", "51820")
		r.runCmd("ip", "-6", "rule", "del", "lookup", "main", "suppress_prefixlength", "0")
	}

	// 2. 清空 51820 路由表
	r.runCmd("ip", "route", "flush", "table", "51820")
	if r.tunDevice != "" {
		r.runCmd("ip", "-6", "route", "flush", "table", "51820")
	}

	r.configured = false
	r.routesAdded = nil
	r.logger.Info("VPN routes removed")
	return nil
}

// getDefaultGatewayLinux 获取 Linux 默认网关 (FwMark 模式下仅用于日志)
func (r *RouteManager) getDefaultGatewayLinux() (string, error) {
	cmd := exec.Command("ip", "route", "show", "default")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}

	fields := strings.Fields(string(output))
	for i, field := range fields {
		if field == "via" && i+1 < len(fields) {
			return fields[i+1], nil
		}
	}

	return "", fmt.Errorf("default gateway not found")
}

// setupWindows Windows 路由配置
func (r *RouteManager) setupWindows() error {
	// 1. 获取当前默认网关
	gateway, err := r.getDefaultGatewayWindows()
	if err != nil {
		return fmt.Errorf("failed to get default gateway: %w", err)
	}
	r.gateway = gateway
	r.logger.Debug("Current default gateway", "gateway", gateway)

	// 2. 添加到服务器的直接路由（确保 Hysteria 连接不走 VPN）
	r.logger.Debug("Adding direct route to server", "server", r.serverIP, "gateway", gateway)
	if err := r.runCmd("route", "add", r.serverIP, "mask", "255.255.255.255", gateway, "metric", "1"); err != nil {
		r.logger.Warn("Failed to add server route (may already exist)", "error", err)
	} else {
		r.routesAdded = append(r.routesAdded, r.serverIP)
	}

	// 3. 添加 VPN 路由 (0.0.0.0/1 和 128.0.0.0/1 覆盖默认路由)
	r.logger.Debug("Adding VPN routes (IPv4)")
	// 使用接口名称添加路由
	if err := r.runCmd("route", "add", "0.0.0.0", "mask", "128.0.0.0", r.tunGateway, "metric", "5"); err != nil {
		return fmt.Errorf("failed to add route 0.0.0.0/1: %w", err)
	}
	if err := r.runCmd("route", "add", "128.0.0.0", "mask", "128.0.0.0", r.tunGateway, "metric", "5"); err != nil {
		return fmt.Errorf("failed to add route 128.0.0.0/1: %w", err)
	}

	// 4. 添加 IPv6 路由
	if r.tunDevice != "" {
		r.logger.Debug("Adding VPN routes (IPv6)", "device", r.tunDevice)
		// Windows IPv6 路由：使用接口索引或名称
		r.runCmd("netsh", "interface", "ipv6", "add", "route", "::/1", r.tunDevice, "metric=5")
		r.runCmd("netsh", "interface", "ipv6", "add", "route", "8000::/1", r.tunDevice, "metric=5")
	}

	r.configured = true
	r.logger.Info("VPN routes configured successfully")
	return nil
}

// cleanupWindows Windows 路由恢复
func (r *RouteManager) cleanupWindows() error {
	var errs []error

	// 1. 删除 VPN 路由
	r.logger.Debug("Removing VPN routes")
	if err := r.runCmd("route", "delete", "0.0.0.0", "mask", "128.0.0.0"); err != nil {
		errs = append(errs, err)
	}
	if err := r.runCmd("route", "delete", "128.0.0.0", "mask", "128.0.0.0"); err != nil {
		errs = append(errs, err)
	}

	// 删除 IPv6 路由
	if r.tunDevice != "" {
		r.runCmd("netsh", "interface", "ipv6", "delete", "route", "::/1", r.tunDevice)
		r.runCmd("netsh", "interface", "ipv6", "delete", "route", "8000::/1", r.tunDevice)
	}

	// 2. 删除服务器直接路由
	for _, route := range r.routesAdded {
		r.logger.Debug("Removing server route", "route", route)
		if err := r.runCmd("route", "delete", route); err != nil {
			errs = append(errs, err)
		}
	}

	r.configured = false
	r.routesAdded = nil

	if len(errs) > 0 {
		r.logger.Warn("Some routes could not be removed", "errors", errs)
	} else {
		r.logger.Info("Original routes restored")
	}

	return nil
}

// getDefaultGatewayWindows 获取 Windows 默认网关
func (r *RouteManager) getDefaultGatewayWindows() (string, error) {
	cmd := exec.Command("route", "print", "0.0.0.0")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		// 寻找 0.0.0.0 开头的行
		if len(fields) >= 3 && fields[0] == "0.0.0.0" {
			// 格式: 0.0.0.0  0.0.0.0  网关  接口  跃点
			return fields[2], nil
		}
	}

	return "", fmt.Errorf("default gateway not found")
}

// runCmd 执行命令
func (r *RouteManager) runCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v: %s - %s", name, args, err, string(output))
	}
	return nil
}
