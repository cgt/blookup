package main

import (
	"net"
	"testing"
)

func TestReverseIPv4(t *testing.T) {
	ip := net.IPv4(203, 0, 113, 1)
	revIP := net.ParseIP(reverseaddr(ip)).To4()
	ip2 := net.IPv4(revIP[3], revIP[2], revIP[1], revIP[0])

	if !ip.Equal(ip2) {
		t.Fatalf("ip != ip2 (%s != %s)", ip, ip2)
	}
}

func TestReverseIPv6(t *testing.T) {
	const correctReversed = "0.8.0.0.0.0.0.0.0.0.0.0.0.0.0.0.f.f.1.a.1.6.f.0.8.b.d.0.1.0.0.2"
	ip := net.ParseIP("2001:db8:f61:a1ff::80")
	revIP := reverseaddr(ip)
	if revIP != correctReversed {
		t.Fatalf("IPv6 addr incorrectly reversed: expected '%v', got '%v'", correctReversed, revIP)
	}
}
