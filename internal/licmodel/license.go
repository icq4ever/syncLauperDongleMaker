package licmodel

import (
	"time"
)

/* ===== 공개 JSON 스키마 (device/binding 미노출) ===== */
type License struct {
	Version     int        `json:"version"`
	Licensee    string     `json:"licensee"`
	LicensePlan string     `json:"license_plan,omitempty"`
	IssuedAt    time.Time  `json:"issued_at"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	SerialKey   string     `json:"serial_key"` // SHA-256(binding || "|" || issued_at_RFC3339)
	Note        string     `json:"note,omitempty"`
}