package device

/* ===== 내부 전용 (노출 금지) ===== */
type Snapshot struct {
	FsUUID        string // UPPER
	PartUUID      string // lower
	PTUUID        string // lower (parent disk PTUUID)
	USBSerialFull string // UPPER (ID_SERIAL), fallback SHORT
}

// 각 백엔드가 “스냅샷을 제공”
type Inspector interface {
	Snapshot() (Snapshot, error)
}

// 각 백엔드가 “쓰기/읽기 기능” 선택적으로 제공
type Writer interface {
	WriteLicense(licBytes, sig []byte) error
}
