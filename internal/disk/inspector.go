// disk inspector
package disk

import (
	"syncLauperDongleMaker/internal/binding"
	"syncLauperDongleMaker/internal/device"
)

// /dev/sdX1 같은 파티션 디바이스 기준 인스펙터
type PartInspector struct {
	PartDev string
}

func (p PartInspector) Snapshot() (device.Snapshot, error) {
	return binding.CollectBindingInfo(p.PartDev)
}