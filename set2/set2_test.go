package set2

import (
	"bytes"
	"crypto/aes"
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/GiorgosMarga/cryptopals/set1"
)

func TestChallenge9(t *testing.T) {
	block := []byte("YELLOW SUBMARINE")
	expectedOutput := []byte{89, 69, 76, 76, 79, 87, 32, 83, 85, 66, 77, 65, 82, 73, 78, 69, 4, 4, 4, 4}
	padded := PKCS7Padding(block, 20)
	if !bytes.Equal(padded, expectedOutput) {
		t.Error("wrong output")
	}
}

func TestChallenge10(t *testing.T) {
	key := []byte("YELLOW SUBMARINE")
	iv := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	f, err := os.Open("ch10.txt")
	if err != nil {
		t.Error(err)
	}
	defer f.Close()
	b, _ := io.ReadAll(f)
	b = bytes.ReplaceAll(b, []byte{'\n'}, []byte{})
	// b, _ = set1.Base64Decode(b)

	// msg := []byte("1234567891234567")
	encrypted := EncryptCBC(b, key, iv)
	fmt.Println(string(encrypted))
	decrypted := DecryptCBC(encrypted, key, iv)
	if !bytes.Equal(decrypted, b) {
		t.Error("Different messages")
	}
}

func TestChallenge11(t *testing.T) {
	b := []byte("Lorem ipsum dolor sit amet, consectetur adipiscing elit aliquam.Lorem ipsum dolor sit amet, consectetur adipiscing elit aliquam.")
	for range 100000 {
		encrypted, method := EncryptionOracle(b)
		oracleMethd := DecryptionOracle(encrypted)
		if oracleMethd != method {
			fmt.Println("Oh no")
		}
	}
}

func TestChallenge12(t *testing.T) {
	plainText, _ := set1.Base64Decode([]byte(randomBytes))
	blockSize := findECBCipherSize()
	predicted := PKCS7PaddingUnpad(FindBlocks(blockSize))
	if !bytes.Equal(plainText, predicted) {
		// fmt.Println("Plain text:", plainText, len(plainText))
		// fmt.Println("Predicted:", predicted, len(predicted))
		fmt.Printf("Predicted size: %d\n", len(predicted))
		fmt.Printf("Actual size: %d\n", len(plainText))
		t.Errorf("wrong result")
	}

}

func TestChallenge13(t *testing.T) {
	key := generateRandomAESKey()
	userEmail := "foooo@bar.com"
	// 10 because + 6 from "email="
	encodedUser := profileFor([]byte(userEmail))
	paddedUser := PKCS7Padding(encodedUser, 16)
	fmt.Println("Padded user:")
	for i := 0; i < len(paddedUser); i += 16 {
		fmt.Println(string(paddedUser[i : i+16]))
	}
	fmt.Println("----------------------")

	badUser := make([]byte, 0, len(paddedUser)+aes.BlockSize)
	badUser = append(badUser, paddedUser[:16]...)
	badUser = append(badUser, PKCS7Padding([]byte("admin"), aes.BlockSize)...)
	badUser = append(badUser, paddedUser[16:]...)
	for i := 0; i < len(badUser); i += 16 {
		fmt.Println(string(badUser[i : i+16]))
	}
	fmt.Println("----------------------")
	// Changing order
	newPaddedUser := make([]byte, 0, len(paddedUser)-aes.BlockSize)
	newPaddedUser = append(newPaddedUser, badUser[0:16]...)
	newPaddedUser = append(newPaddedUser, badUser[32:48]...)
	newPaddedUser = append(newPaddedUser, badUser[16:32]...)
	for i := 0; i < len(newPaddedUser); i += 16 {
		fmt.Println(string(newPaddedUser[i : i+16]))
	}
	fmt.Println("----------------------")

	encryptedUser := EncryptEncodedUser(newPaddedUser, key)
	decryptedUser := DecryptEncodedUser(encryptedUser, key)
	for k, v := range decryptedUser {
		fmt.Println(k, string(PKCS7PaddingUnpad([]byte(v))))
	}
}

// func copyWithCopy() {
// 	b := make([]byte, 10)
// 	b1 := []byte{1, 2, 3}
// 	b2 := []byte{4, 5, 6, 7, 8, 9, 10}
// 	copy(b, b1)
// 	copy(b[len(b1):], b2)
// }

// func copyWithAppend() {
// 	b := make([]byte, 3, 10)
// 	b1 := []byte{1, 2, 3}
// 	b2 := []byte{4, 5, 6, 7, 8, 9, 10}
// 	copy(b, b1)
// 	b = append(b, b2...)
// }

// func copyWithBadAppend() {
// 	b := make([]byte, 0)
// 	b1 := []byte{1, 2, 3}
// 	b2 := []byte{4, 5, 6, 7, 8, 9, 10}
// 	b = append(b, b1...)
// 	b = append(b, b2...)
// }

// func BenchmarkCopy(b *testing.B) {
// 	for i := 0; i < b.N; i++ {
// 		for j := 0; j < 1000; j++ {
// 			copyWithCopy()
// 		}
// 	}
// }

// func BenchmarkCopyAppend(b *testing.B) {
// 	for i := 0; i < b.N; i++ {
// 		for j := 0; j < 1000; j++ {
// 			copyWithAppend()
// 		}
// 	}
// }

// func BenchmarkCopyBadAppend(b *testing.B) {
// 	for i := 0; i < b.N; i++ {
// 		for j := 0; j < 1000; j++ {
// 			copyWithBadAppend()
// 		}
// 	}
// }
