package licmodel

import "time"

type License struct {
	Version     int        `json:"version"`
	Licensee    string     `json:"licensee"`
	LicensePlan string     `json:"license_plan"`
	IssuedAt    time.Time  `json:"issued_at"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	SerialKey   string     `json:"serial_key"`
	Note				string     `json:"note,omitempty"`
}