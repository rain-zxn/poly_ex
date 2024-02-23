package poly_ex

import "encoding/hex"

const (
	MAIN_URL              = "http://seed1.poly.network:20336"
	MAIN_BOOKEEPER_HEIGHT = uint64(30321214)
	TEST_URL              = "http://beta1.poly.network:20336"
	TEST_BOOKEEPER_HEIGHT = uint64(58899233)
)

func HexStringReverse(value string) string {
	aa, _ := hex.DecodeString(value)
	bb := HexReverse(aa)
	return hex.EncodeToString(bb)
}

func HexReverse(arr []byte) []byte {
	l := len(arr)
	x := make([]byte, 0)
	for i := l - 1; i >= 0; i-- {
		x = append(x, arr[i])
	}
	return x
}
