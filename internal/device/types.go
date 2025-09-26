package device

// 공통 스냅샷
type Snapshot struct {
	FsUUID        string
	PartUUID      string
	PTUUID        string
	USBSerialFull string
}

// 각 백엔드가 “스냅샷을 제공”
type Inspector interface {
	Snapshot() (Snapshot, error)
}

// 각 백엔드가 “쓰기/읽기 기능” 선택적으로 제공
type Writer interface {
	WriteLicense(licBytes, sig []byte) error
}
