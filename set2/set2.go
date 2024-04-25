package set2

func PKCS7Padding(b []byte, n int) []byte {
	paddingSize := n - len(b)
	res := make([]byte, n)
	copy(res, b)
	for i := len(b); i < n; i++ {
		res[i] = byte(paddingSize)
	}
	return res
}
