package main

// or, a place you'd really like to have basic generics

// DO I REALLY HAVE TO TELL YOU NOT TO USE THIS? No, I really don't, and
// am kind of flattering myself by even saying it out loud, but on the 
// off chance it isn't clear: DON'T USE THIS. YOU ARE CRAZY. GO AWAY.

import (
	"crypto/cipher"
	"fmt"
	"errors"
	"encoding/binary"
)	

// n = word size (16, 24, 32, 48, or 64)
// m = number of key words (must be 4 if n = 16,
//				3 or 4 if n = 24 or 32,
//				2 or 3 if n = 48,
//				2 or 3 or 4 if n = 64)
// T = rounds = 22 
//		if n = 16
//		= 22 or 23 if n = 24, m = 3 or 4
//		= 26 or 27 if n = 32, m = 3 or 4
//		= 28 or 29 if n = 48, m = 2 or 3
//		= 32, 33, or 34 if n = 64, m = 2, 3, or 4

func kx_64_256(ink [4]uint64) (outk [34]uint64) {
	T := uint(34)
	m := uint(4)
	n := uint(64)

	_rcs := func(w uint64, s uint) uint64 { return (w >> s) | (w << (n-s)); }
	_lcs := func(w uint64, s uint) uint64 { return (w << s) | (w >> (n-s)); }
	
	outk[0] = ink[0]

	for i := uint(0); i < (T-1); i++ {
		idx := 1 + i % (m-1)

		ink[idx] = _rcs(ink[idx], 8)
		ink[idx] += ink[0]
		ink[idx] ^= uint64(i)
		ink[0] = _lcs(ink[0], 3)
		ink[0] ^= ink[idx]		

		outk[i + 1] = ink[0]
	}

	return
}

func enc_64_256(block [2]uint64, kx [34]uint64) [2]uint64 {
	T := uint(34)
	n := uint(64)

	_rcs := func(w uint64, s uint) uint64 { return (w >> s) | (w << (n-s)); }
	_lcs := func(w uint64, s uint) uint64 { return (w << s) | (w >> (n-s)); }

	for i := uint(0); i < T; i++ {
		block[1] = _rcs(block[1], 8)
		block[1] += block[0]
		block[1] ^= kx[i]
		block[0] = _lcs(block[0], 3)
		block[0] ^= block[1]		
	}

	return block
}

func dec_64_256(block [2]uint64, kx [34]uint64) [2]uint64 {
	T := uint(34)
	n := uint(64)

	_rcs := func(w uint64, s uint) uint64 { return (w >> s) | (w << (n-s)); }
	_lcs := func(w uint64, s uint) uint64 { return (w << s) | (w >> (n-s)); }

	for i := T; i > 0; i-- {
		block[0] ^= block[1]
		block[0] = _rcs(block[0], 3)
		block[1] ^= kx[i-1]
		block[1] -= block[0]
		block[1] = _lcs(block[1], 8)
	}

	return block
}

func kx_32_128(ink [4]uint32) (outk [27]uint32) {
	T := uint(27)
	m := uint(4)
	n := uint(32)

	_rcs := func(w uint32, s uint) uint32 { return (w >> s) | (w << (n-s)); }
	_lcs := func(w uint32, s uint) uint32 { return (w << s) | (w >> (n-s)); }
	
	outk[0] = ink[0]

	for i := uint(0); i < (T-1); i++ {
		idx := 1 + i % (m-1)

		ink[idx] = _rcs(ink[idx], 8)
		ink[idx] += ink[0]
		ink[idx] ^= uint32(i)
		ink[0] = _lcs(ink[0], 3)
		ink[0] ^= ink[idx]		

		outk[i + 1] = ink[0]
	}

	return
}

func enc_32_128(block [2]uint32, kx [27]uint32) [2]uint32 {
	T := uint(27)
	n := uint(32)

	_rcs := func(w uint32, s uint) uint32 { return (w >> s) | (w << (n-s)); }
	_lcs := func(w uint32, s uint) uint32 { return (w << s) | (w >> (n-s)); }

	for i := uint(0); i < T; i++ {
		block[1] = _rcs(block[1], 8)
		block[1] += block[0]
		block[1] ^= kx[i]
		block[0] = _lcs(block[0], 3)
		block[0] ^= block[1]		
	}

	return block
}

func dec_32_128(block [2]uint32, kx [27]uint32) [2]uint32 {
	T := uint(27)
	n := uint(32)

	_rcs := func(w uint32, s uint) uint32 { return (w >> s) | (w << (n-s)); }
	_lcs := func(w uint32, s uint) uint32 { return (w << s) | (w >> (n-s)); }

	for i := T; i > 0; i-- {
		block[0] ^= block[1]
		block[0] = _rcs(block[0], 3)
		block[1] ^= kx[i-1]
		block[1] -= block[0]
		block[1] = _lcs(block[1], 8)
	}

	return block
}

func kx_16_64(ink [4]uint16) (outk [22]uint16) {
	T := uint(22)
	m := uint(4)
	n := uint(16)

	_rcs := func(w uint16, s uint) uint16 { return (w >> s) | (w << (n-s)); }
	_lcs := func(w uint16, s uint) uint16 { return (w << s) | (w >> (n-s)); }
	
	outk[0] = ink[0]

	for i := uint(0); i < (T-1); i++ {
		idx := 1 + i % (m-1)

		ink[idx] = _rcs(ink[idx], 7)
		ink[idx] += ink[0]
		ink[idx] ^= uint16(i)
		ink[0] = _lcs(ink[0], 2)
		ink[0] ^= ink[idx]		

		outk[i + 1] = ink[0]
	}

	return
}

func enc_16_64(block [2]uint16, kx [22]uint16) [2]uint16 {
	T := uint(22)
	n := uint(16)

	_rcs := func(w uint16, s uint) uint16 { return (w >> s) | (w << (n-s)); }
	_lcs := func(w uint16, s uint) uint16 { return (w << s) | (w >> (n-s)); }

	for i := uint(0); i < T; i++ {
		block[1] = _rcs(block[1], 7)
		block[1] += block[0]
		block[1] ^= kx[i]
		block[0] = _lcs(block[0], 2)
		block[0] ^= block[1]		
	}

	return block
}

func dec_16_64(block [2]uint16, kx [22]uint16) [2]uint16 {
	T := uint(22)
	n := uint(16)

	_rcs := func(w uint16, s uint) uint16 { return (w >> s) | (w << (n-s)); }
	_lcs := func(w uint16, s uint) uint16 { return (w << s) | (w >> (n-s)); }

	for i := T; i > 0; i-- {
		block[0] ^= block[1]
		block[0] = _rcs(block[0], 2)
		block[1] ^= kx[i-1]
		block[1] -= block[0]
		block[1] = _lcs(block[1], 7)
	}

	return block
}

// Test vectors (these should all pass, but note they're reversed):
//
// Speck32/64
// { 0x1918, 0x1110, 0x0908, 0x0100, }
// { 0x6574, 0x694c, }
// { 0xa868, 0x42f2, }
// Speck48/72
// { 0x121110, 0x0a0908, 020100, }
// { 0x20796c, 0x6c6172, }
// { 0xc049a5, 0x385adc, }
// Speck48/96
// { 0x1a1918, 0x121110, 0x0a0908, 0x020100, }
// { 0x6d2073, 0x696874, }
// { 0x735e10, 0xb6445d, }
// Speck64/96
// { 0x13121110, 0x0b0a0908, 0x03020100, }
// { 0x74614620, 0x736e6165, }
// { 0x9f7952ec, 0x4175946c, }
// Speck64/128
// { 0x1b1a1918, 0x13121110, 0x0b0a0908, 0x03020100, }
// { 0x3b726574, 0x7475432d, }
// { 0x8c6fa548, 0x454e028b, }
// Speck96/96
// { 0x0d0c0b0a0908, 0x050403020100, }
// { 0x65776f68202c, 0x656761737520, }
// { 0x9e4d09ab7178, 0x62bdde8f79aa, }
// Speck96/144
// { 0x151413121110, 0x0d0c0b0a0908, 0x050403020100, }
// { 0x656d6974206e, 0x69202c726576, }
// { 0x2bf31072228a, 0x7ae440252ee6, }
// Speck128/128
// { 0x0f0e0d0c0b0a0908, 0x0706050403020100, }
// { 0x6c61766975716520, 0x7469206564616d20, }
// { 0xa65d985179783265, 0x7860fedf5c570d18, }
// Speck128/192
// { 0x1716151413121110, 0x0f0e0d0c0b0a0908, 0706050403020100, }
// { 0x7261482066656968, 0x43206f7420746e65, }
// { 0x1be4cf3a13135566, 0xf9bc185de03c1886, }
// Speck128/256
// { 0x1f1e1d1c1b1a1918, 0x1716151413121110, 0f0e0d0c0b0a0908, 0706050403020100, }
// { 0x65736f6874206e49, 0x202e72656e6f6f70, }
// { 0x4109010405c0f53e, 0x4eeeb48d9c188f43, }

// 64 bit word
type speck128k256 struct {
	xk [34]uint64
}

func (c *speck128k256) BlockSize() int { return 16; }

type xfrm128 func([2]uint64, [34]uint64) [2]uint64;

func (c *speck128k256) xfrm(dst, src []byte, fn xfrm128) {
	var block [2]uint64
	block[0] = binary.BigEndian.Uint64(src[0:])
	block[1] = binary.BigEndian.Uint64(src[8:])
	ct := fn(block, c.xk)
	binary.BigEndian.PutUint64(dst[0:], ct[0])
	binary.BigEndian.PutUint64(dst[8:], ct[1])
}

func (c *speck128k256) Decrypt(dst, src []byte) { c.xfrm(dst, src, dec_64_256) }
func (c *speck128k256) Encrypt(dst, src []byte) { c.xfrm(dst, src, enc_64_256) }

// 32 bit word
type speck64k128 struct {
	xk [27]uint32
}

func (c *speck64k128) BlockSize() int { return 8; }

type xfrm64 func([2]uint32, [27]uint32) [2]uint32;

func (c *speck64k128) xfrm(dst, src []byte, fn xfrm64) {
	var block [2]uint32
	block[0] = binary.BigEndian.Uint32(src[0:])
	block[1] = binary.BigEndian.Uint32(src[4:])
	ct := fn(block, c.xk)
	binary.BigEndian.PutUint32(dst[0:], ct[0])
	binary.BigEndian.PutUint32(dst[4:], ct[1])
}

func (c *speck64k128) Decrypt(dst, src []byte) { c.xfrm(dst, src, dec_32_128) ; }
func (c *speck64k128) Encrypt(dst, src []byte) { c.xfrm(dst, src, enc_32_128) ; }

// 16 bit word
type speck32k64 struct {
	xk [22]uint16
}

func (c *speck32k64) BlockSize() int { return 4; }

type xfrm32 func([2]uint16, [22]uint16) [2]uint16;

func (c *speck32k64) xfrm(dst, src []byte, fn xfrm32) {
	var block [2]uint16
	block[0] = binary.BigEndian.Uint16(src[0:])
	block[1] = binary.BigEndian.Uint16(src[2:])
	ct := fn(block, c.xk)
	binary.BigEndian.PutUint16(dst[0:], ct[0])
	binary.BigEndian.PutUint16(dst[2:], ct[1])
}

func (c *speck32k64) Decrypt(dst, src []byte) { c.xfrm(dst, src, dec_16_64) ; }
func (c *speck32k64) Encrypt(dst, src []byte) { c.xfrm(dst, src, enc_16_64) ; }

type specksz int

var B128K256 specksz = 64
var B64K128 specksz = 32
var B32K64 specksz = 16

func NewCipher(k []byte, ws specksz) (cipher.Block, error) {
	switch ws {
	case B128K256:
		var ink [4]uint64
		for i := 0; i < 3; i++ {
			ink[i] = binary.BigEndian.Uint64(k[i * 8:])
		}
		return &speck128k256{
			xk: kx_64_256(ink),
		}, nil
	case B64K128:
		var ink [4]uint32
		for i := 0; i < 3; i++ {
			ink[i] = binary.BigEndian.Uint32(k[i * 4:])
		}
		return &speck64k128{
			xk: kx_32_128(ink),
		}, nil
	case B32K64:
		var ink [4]uint16
		for i := 0; i < 3; i++ {
			ink[i] = binary.BigEndian.Uint16(k[i * 2:])
		}
		return &speck32k64{
			xk: kx_16_64(ink),
		}, nil
	}

	return nil, errors.New("bad key size")
}

func main() { 
	pt := []byte(`
I have passed with a nod of the head
Or polite meaningless words,
Or have lingered awhile and said
Polite meaningless words,
`)
	k := []byte("DOT DASH DOT DASH DOT DASH DASH!")

	c, err := NewCipher(k, B128K256)
	if err != nil {
		fmt.Println(err)
		return
	}

	iv := make([]byte, 0)
	for i := 0; i < c.BlockSize(); i++ {
		iv = append(iv, byte(0))
	}

	spill := len(pt) % c.BlockSize()
	if spill == 0 {
		for i := 0; i < c.BlockSize(); i++ {
			pt = append(pt, byte(c.BlockSize()))
		}
	} else {
		pad := c.BlockSize() - spill
		for i := 0; i < pad; i++ {
			pt = append(pt, byte(pad))
		}
	}	

	mode := cipher.NewCBCEncrypter(c, iv)
	ciphertext := make([]byte, len(pt))
	mode.CryptBlocks(ciphertext, pt)

	fmt.Println(ciphertext)
	
	mode = cipher.NewCBCDecrypter(c, iv)
	mode.CryptBlocks(pt, ciphertext)

	fmt.Println(string(pt))
}
