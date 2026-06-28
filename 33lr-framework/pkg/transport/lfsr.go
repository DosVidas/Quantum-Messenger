package transport

import (
	"time"
)

// LFSR implements a Linear Feedback Shift Register for frequency hopping.
type LFSR struct {
	state uint16
	mask  uint16
}

// NewLFSR creates a new LFSR with a given seed.
func NewLFSR(seed uint16) *LFSR {
	if seed == 0 {
		seed = uint16(time.Now().UnixNano())
	}
	return &LFSR{
		state: seed,
		mask:  0xB400, // Taps for 16-bit LFSR: 16, 14, 13, 11
	}
}

// Next returns the next pseudo-random value.
func (l *LFSR) Next() uint16 {
	bit := (l.state ^ (l.state >> 2) ^ (l.state >> 3) ^ (l.state >> 5)) & 1
	l.state = (l.state >> 1) | (bit << 15)
	return l.state
}

// GetJitterInterval returns a pseudo-random interval between min and max ms.
func (l *LFSR) GetJitterInterval(min, max int) time.Duration {
	val := l.Next()
	ms := int(val)% (max - min + 1) + min
	return time.Duration(ms) * time.Millisecond
}

// GetNextPort selects a port from a list based on LFSR state.
func (l *LFSR) GetNextPort(ports []int) int {
	val := l.Next()
	return ports[int(val)%len(ports)]
}
