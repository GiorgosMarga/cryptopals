package set1

import (
	"crypto/aes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"unicode"
)

func HexToBase64(b []byte) ([]byte, error) {
	decoded := make([]byte, hex.DecodedLen(len(b)))
	if _, err := hex.Decode(decoded, b); err != nil {
		return nil, err
	}
	encoded := make([]byte, base64.StdEncoding.EncodedLen(len(decoded)))
	base64.StdEncoding.Encode(encoded, decoded)

	return encoded, nil
}
func Base64ToHex(b []byte) ([]byte, error) {
	decoded := make([]byte, base64.StdEncoding.DecodedLen(len(b)))
	if _, err := base64.StdEncoding.Decode(decoded, b); err != nil {
		return nil, err
	}
	encoded := make([]byte, hex.EncodedLen(len(decoded)))
	hex.Encode(encoded, decoded)
	return encoded, nil
}
func HexDecode(b []byte) ([]byte, error) {
	res := make([]byte, hex.DecodedLen(len(b)))
	if _, err := hex.Decode(res, b); err != nil {
		return nil, err
	}
	return res, nil
}

func HexEncode(b []byte) []byte {
	res := make([]byte, hex.EncodedLen(len(b)))
	hex.Encode(res, b)
	return res
}

func Base64Decode(b []byte) ([]byte, error) {
	decoded := make([]byte, base64.StdEncoding.DecodedLen(len(b)))
	if _, err := base64.StdEncoding.Decode(decoded, b); err != nil {
		return nil, err
	}
	return decoded, nil
}
func XOR(b1, b2 []byte) ([]byte, error) {
	if len(b1) != len(b2) {
		return nil, fmt.Errorf("b1 and b2 have different size")
	}
	output := make([]byte, len(b1))
	for i := range b1 {
		output[i] = b1[i] ^ b2[i]
	}
	return output, nil
}

func SingleByteXOR(b []byte, k byte) []byte {
	res := make([]byte, len(b))
	for i := range b {
		res[i] = b[i] ^ k
	}
	return res
}
func RepeatingXOR(b1 []byte, k []byte) []byte {
	ptr := 0
	res := make([]byte, len(b1))
	for i := range b1 {
		res[i] = b1[i] ^ k[ptr]
		ptr = (ptr + 1) % len(k)
	}
	return res
}
func BreakSingleByteXOR(b []byte) ([]byte, byte) {
	var (
		res       []byte
		bestByte  byte
		bestScore float64 = 0
	)
	for i := range 256 {
		xored := SingleByteXOR(b, byte(i))
		sc := calculateScore(xored)
		if sc > bestScore {
			bestScore = sc
			res = xored
			bestByte = byte(i)
		}
	}
	return res, bestByte
}
func BreakRepeatingXOR(b []byte) ([]byte, error) {
	keysize := findKeySize(b)
	key := make([]byte, 0, keysize)
	blocks := makeBlocks(b, keysize)
	transposed := transposeBlocks(blocks)
	for _, block := range transposed {
		_, k := BreakSingleByteXOR(block)
		key = append(key, k)
	}
	res := RepeatingXOR(b, key)
	fmt.Println(string(res))
	return nil, nil
}

func DecryptECB(b []byte, key []byte) []byte {
	cipher, _ := aes.NewCipher(key)
	decrypted := make([]byte, len(b))
	size := 16 // block size

	for bs, be := 0, size; bs < len(b); bs, be = bs+size, be+size {
		cipher.Decrypt(decrypted[bs:be], b[bs:be])
	}

	return decrypted
}
func EncryptECB(b []byte, key []byte) []byte {
	cipher, _ := aes.NewCipher(key)
	encrypted := make([]byte, len(b))
	size := 16 // block size

	for bs, be := 0, size; bs < len(b); bs, be = bs+size, be+size {
		cipher.Encrypt(encrypted[bs:be], b[bs:be])
	}

	return encrypted
}
func makeECBBlocks(b []byte) [][]byte {
	n := len(b)
	res := make([][]byte, n/16)

	for i := 0; i < n/16; i++ {
		res[i] = b[i*16 : i*16+16]
	}
	return res
}
func isLetter(b byte) bool {
	return (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') || b == ' '
}
func findKeySize(b []byte) int {
	minHamDist := float64(len(b) * 100)
	bestKeySize := 0
	for keysize := 2; keysize <= 40; keysize++ {
		b1 := b[:keysize]
		b2 := b[keysize : 2*keysize]
		b3 := b[2*keysize : 3*keysize]
		b4 := b[3*keysize : 4*keysize]
		hammingDistances := sum(hammingDistance(b1, b2), hammingDistance(b2, b3), hammingDistance(b3, b4), hammingDistance(b4, b1), hammingDistance(b1, b3), hammingDistance(b2, b4))
		avgDis := float64(hammingDistances) / float64(6)
		hammingDist := avgDis / float64(keysize)
		if hammingDist < minHamDist {
			minHamDist = hammingDist
			bestKeySize = keysize
		}
	}
	return bestKeySize
}
func sum(vals ...int) int {
	var res int
	for _, v := range vals {
		res += v
	}
	return res
}
func calculateScore(b []byte) float64 {
	freq := map[byte]float64{'E': 12.70, 'T': 9.06, 'A': 8.17, 'O': 7.51, 'I': 6.97, 'N': 6.75, 'S': 6.33,
		'H': 6.09,
		'R': 5.99, 'D': 4.25, 'L': 4.03, 'C': 2.78, 'U': 2.76, 'M': 2.41, 'W': 2.36,
		'F': 2.23,
		'G': 2.02, 'Y': 1.97, 'P': 1.93, 'B': 1.29, 'V': 0.98, 'K': 0.77, 'J': 0.15,
		'X': 0.15,
		'Q': 0.10, 'Z': 0.07, ' ': 35}
	var score float64 = 0.0

	for _, v := range b {
		if isLetter(v) {
			score += freq[byte(unicode.ToUpper(rune(v)))]
		}
	}
	return score
}

func hammingDistance(b1, b2 []byte) int {
	res := 0
	binaryB1 := toBinary(b1)
	binaryB2 := toBinary(b2)
	for i := range binaryB1 {
		if binaryB1[i] != binaryB2[i] {
			res++
		}
	}
	return res
}
func toBinary(s []byte) string {
	res := ""
	for _, c := range s {
		res = fmt.Sprintf("%s%.8b", res, c)
	}
	return res
}

func makeBlocks(b []byte, keysize int) [][]byte {
	n := len(b)
	numBlocks := n / keysize
	res := make([][]byte, numBlocks)
	i := 0
	for i = 0; i < numBlocks; i++ {
		res[i] = b[i*keysize : i*keysize+keysize]
	}
	remaining := make([]byte, 0)
	for j := (i-1)*keysize + keysize; j < len(b); j++ {
		remaining = append(remaining, b[j])
	}
	res = append(res, remaining)
	return res
}

func transposeBlocks(b [][]byte) [][]byte {
	res := make([][]byte, len(b[0]))
	for i := 0; i < len(b[0]); i++ {
		bl := make([]byte, 0, len(b))
		for j := 0; j < len(b); j++ {
			if i < len(b[j]) {
				bl = append(bl, b[j][i])
			}
		}
		res[i] = bl
	}
	return res
}
