//go:build !windows

// Package wintun 提供 Windows 平台的 Wintun DLL 嵌入和加载功能
// 非 Windows 平台的空实现
package wintun

// EnsureLoaded 在非 Windows 平台上不需要任何操作
func EnsureLoaded() error {
	return nil
}
