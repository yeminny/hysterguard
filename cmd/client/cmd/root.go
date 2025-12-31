// Package cmd 提供客户端 CLI 命令
package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/hysterguard/hysterguard/internal/config"
	"github.com/hysterguard/hysterguard/internal/tunnel"
	"github.com/hysterguard/hysterguard/internal/wintun"
)

var (
	configFile string
	logLevel   string
)

var rootCmd = &cobra.Command{
	Use:   "hysterguard-client",
	Short: "HysterGuard Client - Hysteria + WireGuard VPN",
	Long: `HysterGuard Client combines Hysteria 2 obfuscation with WireGuard encryption.

Hysteria provides the outer QUIC transport layer with Salamander obfuscation,
while WireGuard handles the inner encrypted VPN tunnel.`,
	RunE: runClient,
}

func init() {
	rootCmd.Flags().StringVarP(&configFile, "config", "c", "config.yaml", "Path to configuration file")
	rootCmd.Flags().StringVarP(&logLevel, "log-level", "l", "info", "Log level (debug, info, warn, error)")
}

// Execute 执行根命令
func Execute() error {
	return rootCmd.Execute()
}

func runClient(cmd *cobra.Command, args []string) error {
	// 设置日志
	level := slog.LevelInfo
	switch logLevel {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
	slog.SetDefault(logger)

	logger.Info("Starting HysterGuard Client",
		"version", "0.1.0",
		"config", configFile,
	)

	// 加载配置
	cfg, err := config.LoadClientConfig(configFile)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// 验证配置
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("invalid config: %w", err)
	}

	logger.Debug("Configuration loaded",
		"server", cfg.Hysteria.Server,
		"obfs", cfg.Hysteria.Obfs.Type,
	)

	// Windows: 确保 wintun.dll 已加载
	if err := wintun.EnsureLoaded(); err != nil {
		return fmt.Errorf("failed to load wintun: %w", err)
	}

	// 创建隧道
	tun, err := tunnel.NewClientTunnel(cfg, logger)
	if err != nil {
		return fmt.Errorf("failed to create tunnel: %w", err)
	}

	// 启动隧道
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := tun.Start(ctx); err != nil {
		return fmt.Errorf("failed to start tunnel: %w", err)
	}

	logger.Info("HysterGuard tunnel is now running")
	logger.Info("Press Ctrl+C to stop")

	// 等待信号
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-sigCh:
		logger.Info("Received signal, shutting down", "signal", sig)
	case <-tun.Wait():
		logger.Warn("Tunnel closed unexpectedly")
	}

	// 停止隧道
	if err := tun.Stop(); err != nil {
		logger.Error("Error during shutdown", "error", err)
	}

	logger.Info("HysterGuard Client stopped")
	return nil
}
