package set1

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
)

func TestChallenge1(t *testing.T) {
	data := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	output := "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
	b64, err := HexToBase64([]byte(data))
	if err != nil {
		t.Fail()
	}
	if output != string(b64) {
		t.Errorf("Diff\nOuput: (%s)\nB64: (%s)\n", output, string(b64))
	}
}

func TestChallenge2(t *testing.T) {
	var (
		data       = "1c0111001f010100061a024b53535009181c"
		xorAgainst = "686974207468652062756c6c277320657965"
		output     = "746865206b696420646f6e277420706c6179"
		b1         []byte
		b2         []byte
		err        error
	)
	if b1, err = HexDecode([]byte(data)); err != nil {
		t.FailNow()
	}
	if b2, err = HexDecode([]byte(xorAgainst)); err != nil {
		t.FailNow()
	}
	b, err := XOR(b1, b2)
	if err != nil {
		t.Errorf("Error xoring %s", err)
	}
	res := HexEncode(b)
	if string(res) != output {
		t.FailNow()
	}
}

func TestChallenge3(t *testing.T) {
	var (
		bestScore float64 = 0
		res       string
	)
	cipher := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	decoded, err := HexDecode([]byte(cipher))
	if err != nil {
		t.Error(err)
	}

	for i := range 255 {
		xored := SingleByteXOR(decoded, byte(i))
		sc := calculateScore(xored)
		if sc > bestScore {
			bestScore = sc
			res = string(xored)
		}
	}
	if res != "Cooking MC's like a pound of bacon" {
		t.Fail()
	}
}

func TestChallenge4(t *testing.T) {
	filename := "ch4.txt"
	f, err := os.Open(filename)
	if err != nil {
		t.Error(err)
	}
	defer f.Close()

	content, err := io.ReadAll(f)
	if err != nil {
		t.Error(err)
	}

	lines := strings.Split(string(content), "\n")
	var (
		bestScore float64 = 0
		res       string
	)
	for _, line := range lines {
		decoded, err := HexDecode([]byte(line))
		if err != nil {
			t.Error(err)
		}
		dec, _ := BreakSingleByteXOR(decoded)
		score := calculateScore(dec)
		if score > bestScore {
			bestScore = score
			res = string(dec)
		}
	}
	fmt.Println(res)
	if res != "Now that the party is jumping\n" {
		t.Fail()
	}
}

func TestChallenge5(t *testing.T) {
	data := "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
	key := "ICE"
	expectedOutput := "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
	res := RepeatingXOR([]byte(data), []byte(key))
	if expectedOutput != string(HexEncode(res)) {
		t.Error()
	}
}

func TestHammingDistance(t *testing.T) {
	s1 := "this is a test"
	s2 := "wokka wokka!!!"

	distance := hammingDistance([]byte(s1), []byte(s2))
	if distance != 37 {
		t.Errorf("Distanse is %d", distance)
	}

}

func TestMakeBlocks(t *testing.T) {
	data := "12345678901"
	keysize := 2
	blocks := makeBlocks([]byte(data), keysize)
	for _, v := range blocks {
		fmt.Println(string(v))
	}
	transposed := transposeBlocks(blocks)
	for _, v := range transposed {
		fmt.Println(string(v))
	}
}
func TestChallenge6(t *testing.T) {
	f, err := os.Open("ch6.txt")
	if err != nil {
		t.Error("error opening file")
	}
	defer f.Close()

	content, err := io.ReadAll(f)
	if err != nil {
		t.Error("error reading file")
	}
	content = removeNewLine(content)
	hEnc, err := Base64Decode(content)
	if err != nil {
		t.Error(err)
	}
	BreakRepeatingXOR(hEnc)
}

func TestChallenge7(t *testing.T) {
	f, err := os.Open("ch7.txt")
	if err != nil {
		t.Error("error opening file")
	}
	defer f.Close()

	content, err := io.ReadAll(f)
	if err != nil {
		t.Error("error reading file")
	}
	content = removeNewLine(content)
	hEnc, err := Base64Decode(content)
	if err != nil {
		t.Error(err)
	}
	key := "YELLOW SUBMARINE"
	decrypted := DecryptECB(hEnc, []byte(key))
	fmt.Println(string(decrypted))
}
func TestChallenge8(t *testing.T) {
	f, err := os.Open("ch8.txt")
	if err != nil {
		t.Error("error opening file")
	}
	defer f.Close()

	content, err := io.ReadAll(f)
	if err != nil {
		t.Error("error reading file")
	}
	lines := strings.Split(string(content), "\n")
	key := "YELLOW SUBMARINE"
	bestCommon := 0
	var bestLine string
	for _, line := range lines {
		line = strings.TrimRight(line, "\n")
		commonWords := 0
		dict := make(map[string]struct{})
		d, _ := HexDecode([]byte(line))
		blocks := makeECBBlocks(d)
		for _, block := range blocks {
			w := DecryptECB(block, []byte(key))
			if _, ok := dict[string(w)]; !ok {
				commonWords++
				dict[string(w)] = struct{}{}
			}
		}
		if commonWords > bestCommon {
			fmt.Println(commonWords)
			bestCommon = commonWords
			bestLine = line
		}
	}
	fmt.Println(string(bestLine))
}
func removeNewLine(b []byte) []byte {
	return bytes.ReplaceAll(b, []byte{'\n'}, []byte{})
}
