package utils

import(

)

func SubtleConstTimeEq(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte = 0
	for i := 0; i < len(a); i++ {
		v |= a[i] ^ b[i]
	}
	return v == 0
}