package set2

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"fmt"
	"log"
	mathr "math/rand/v2"

	"github.com/GiorgosMarga/cryptopals/set1"
)

var ECBKey = []byte{91, 76, 239, 88, 139, 98, 250, 184, 108, 29, 42, 171, 222, 155, 57, 245}
var randomBytes = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
var myRandomBytes = "SGVsbG8gd29ybGRzCkhlbGxvIHdvcmxkcwpIZWxsbyB3b3JsZHMKSGVsbG8gd29ybGRzCkhlbGxvIHdvcmxkc0hlbGxvIHdvcmxkc0hlbGxvIHdvcmxkcwpIZWxsbyB3b3JsZHNIZWxsbyB3b3JsZHNIZWxsbyB3b3JsZHNIZWxsbyB3b3JsZHNIZWxsbyB3b3JsZHNIZWxsbyB3b3JsZHNIZWxsbyB3b3JsZHMKSGVsbG8gd29ybGRzSGVsbG8gd29ybGRzSGVsbG8gd29ybGRzSGVsbG8gd29ybGRzCkhlbGxvIHdvcmxkc0hlbGxvIHdvcmxkc0hlbGxvIHdvcmxkc0hlbGxvIHdvcmxkcwpIZWxsbyB3b3JsZHNIZWxsbyB3b3JsZHNIZWxsbyB3b3JsZHMKSGVsbG8gd29ybGRzc3Nzcw=="

func PKCS7PaddingUnpad(b []byte) []byte {
	lastByte := b[len(b)-1]
	if lastByte > aes.BlockSize {
		// buffer was not padded
		return b
	}
	unpadded := make([]byte, len(b)-int(lastByte))
	copy(unpadded, b)
	return unpadded
}
func PKCS7Padding(b []byte, blockSize int) []byte {
	if len(b)%blockSize == 0 {
		return b
	}
	n := len(b) / blockSize
	finalSize := blockSize * (n + 1)
	res := make([]byte, finalSize)
	copy(res, b)
	for i := len(b); i < finalSize; i++ {
		res[i] = byte(finalSize - len(b))
	}
	return res
}

func EncryptCBC(b []byte, key []byte, iv []byte) []byte {
	cipher, _ := aes.NewCipher(key)
	encrypted := make([]byte, 0, len(b))
	prev := iv
	for i := 0; i < len(b); i += aes.BlockSize {
		block := PKCS7Padding(b[i:i+aes.BlockSize], aes.BlockSize)
		toEncrypt, _ := set1.XOR(block, prev)
		t := make([]byte, len(block))
		cipher.Encrypt(t, toEncrypt)
		encrypted = append(encrypted, t...)
		prev = encrypted[i : i+aes.BlockSize]
	}
	return encrypted
}

func DecryptCBC(b []byte, key []byte, iv []byte) []byte {
	decrypted := make([]byte, 0)
	prev := iv
	for i := 0; i < len(b); i += aes.BlockSize {
		encryptedBlock := b[i : i+aes.BlockSize]
		decryptedBlock := set1.DecryptECB(encryptedBlock, key)
		plaintext, _ := set1.XOR(decryptedBlock, prev)
		prev = encryptedBlock
		decrypted = append(decrypted, plaintext...)
	}
	return decrypted
}

func OracleECB(b []byte) []byte {
	randomBase64, err := set1.Base64Decode([]byte(randomBytes))
	if err != nil {
		log.Fatal(err)
	}
	appendedText := make([]byte, len(b), len(b)+len(randomBase64))
	copy(appendedText, b)
	appendedText = append(appendedText, randomBase64...)
	return set1.EncryptECB(PKCS7Padding(appendedText, 16), ECBKey)
}

func FindBlocks(blockSize int) []byte {
	res := make([]byte, 0, blockSize)
	checkSize := blockSize

	for {
		found := false
		p := bytes.Repeat([]byte{'X'}, blockSize-1-(len(res)%blockSize))
		actual := OracleECB(p)
		p = append(p, res...)
		p = append(p, byte(10))
		for j := range 256 {
			p[checkSize-1] = byte(j)
			encrypted := OracleECB(p)
			if bytes.Equal(actual[:checkSize], encrypted[:checkSize]) {
				res = append(res, byte(j))
				found = true
				break
			}
		}
		if !found {
			break
		}
		if len(res)%blockSize == 0 {
			checkSize += blockSize
		}
	}
	return res
}

func findECBCipherSize() int {
	b := make([]byte, 0, 100)
	blockSize := 0
	for range 100 {
		b = append(b, 'A')
		encrypted := OracleECB(b)
		if blockSize == 0 {
			blockSize = len(encrypted)
			continue
		}
		if len(encrypted) > blockSize {
			return len(encrypted) - blockSize
		}
	}
	return -1
}

func EncryptionOracle(b []byte) ([]byte, string) {
	key := generateRandomAESKey()
	encrypted := make([]byte, len(b))
	randomBytesBlock := addRandomBytes(b)
	var method string
	n := mathr.IntN(2)
	if n == 0 {
		// ECB
		method = "ECB"
		copy(encrypted, set1.EncryptECB(PKCS7Padding(randomBytesBlock, 16), key))
	} else {
		// CBC
		method = "CBC"
		iv := make([]byte, aes.BlockSize)
		_, _ = rand.Read(iv)
		copy(encrypted, EncryptCBC(PKCS7Padding(randomBytesBlock, 16), key, iv))
	}
	return encrypted, method
}

func DecryptionOracle(b []byte) string {
	encryptedBlocks := make(map[string]struct{}, len(b))
	for i := 0; i < len(b); i += aes.BlockSize {
		if _, ok := encryptedBlocks[string(b[i:i+aes.BlockSize])]; ok {
			return "ECB"
		}
		encryptedBlocks[string(b[i:i+aes.BlockSize])] = struct{}{}
	}
	return "CBC"
}

// for challenge 13
func parser(s []byte) map[string]string {
	splitted := bytes.Split(s, []byte{'&'})
	m := make(map[string]string, len(splitted))
	for _, pair := range splitted {
		spittedPair := bytes.Split(pair, []byte{'='})
		fmt.Println(string(spittedPair[0]), string(spittedPair[1]))

		if len(spittedPair) != 2 {
			log.Fatalf("Wrong line: (%s)\n", pair)
		}
		m[string(spittedPair[0])] = string(spittedPair[1])
	}
	return m
}

func profileFor(email []byte) []byte {
	email = bytes.ReplaceAll(email, []byte{'&'}, []byte{})
	email = bytes.ReplaceAll(email, []byte{'='}, []byte{})
	profile := make([]byte, 0, len("email=")+len("&uid=10&role=user")+len(email))
	profile = append(profile, []byte("email=")...)
	profile = append(profile, email...)
	profile = append(profile, []byte("&uid=10&role=user")...)
	return profile
}

func EncryptEncodedUser(encodedUser []byte, key []byte) []byte {
	return set1.EncryptECB(PKCS7Padding(encodedUser, aes.BlockSize), key)
}
func DecryptEncodedUser(encryptedUser []byte, key []byte) map[string]string {
	decryptedUser := set1.DecryptECB(encryptedUser, key)
	return parser(decryptedUser)
}

func generateRandomAESKey() []byte {
	key := make([]byte, 16)
	_, _ = rand.Read(key)
	return key
}

func addRandomBytes(b []byte) []byte {
	numOfBytes := mathr.IntN(5) + 5
	pre := make([]byte, numOfBytes)
	post := make([]byte, numOfBytes)
	_, _ = rand.Read(pre)
	_, _ = rand.Read(post)
	newB := make([]byte, len(b)+2*numOfBytes)
	copy(newB, pre)
	copy(newB, b)
	copy(newB, post)
	return newB
}
