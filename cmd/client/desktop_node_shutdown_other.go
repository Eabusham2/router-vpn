//go:build !linux

package main

func (*app) retireNativeNodeForShutdown() error { return nil }
