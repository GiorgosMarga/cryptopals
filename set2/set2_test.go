package set2

import (
	"bytes"
	"testing"
)

func TestChallenge9(t *testing.T) {
	block := []byte("YELLOW SUBMARINE")
	expectedOutput := []byte{89, 69, 76, 76, 79, 87, 32, 83, 85, 66, 77, 65, 82, 73, 78, 69, 4, 4, 4, 4}
	padded := PKCS7Padding(block, 20)
	if !bytes.Equal(padded, expectedOutput) {
		t.Error("wrong output")
	}
}
