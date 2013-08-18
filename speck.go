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
	"bytes"
	"sort"
	"math/rand"
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

func rcs64(w uint64, s uint) uint64 { return (w >> s) | (w << (64-s)); }
func lcs64(w uint64, s uint) uint64 { return (w << s) | (w >> (64-s)); }
func rcs32(w uint32, s uint) uint32 { return (w >> s) | (w << (32-s)); }
func lcs32(w uint32, s uint) uint32 { return (w << s) | (w >> (32-s)); }
func rcs16(w uint16, s uint) uint16 { return (w >> s) | (w << (16-s)); }
func lcs16(w uint16, s uint) uint16 { return (w << s) | (w >> (16-s)); }

func kx_64_256(ink [4]uint64) (outk [34]uint64) {
	T := uint(34)
	m := uint(4)
	
	outk[0] = ink[0]

	for i := uint(0); i < (T-1); i++ {
		idx := 1 + i % (m-1)

		ink[idx] = rcs64(ink[idx], 8)
		ink[idx] += ink[0]
		ink[idx] ^= uint64(i)
		ink[0] = lcs64(ink[0], 3)
		ink[0] ^= ink[idx]		

		outk[i + 1] = ink[0]
	}

	return
}

func enc_64_256(block [2]uint64, kx [34]uint64) [2]uint64 {
	T := uint(34)

	for i := uint(0); i < T; i++ {
		block[1] = rcs64(block[1], 8)
		block[1] += block[0]
		block[1] ^= kx[i]
		block[0] = lcs64(block[0], 3)
		block[0] ^= block[1]		
	}

	return block
}

func dec_64_256(block [2]uint64, kx [34]uint64) [2]uint64 {
	T := uint(34)

	for i := T; i > 0; i-- {
		block[0] ^= block[1]
		block[0] = rcs64(block[0], 3)
		block[1] ^= kx[i-1]
		block[1] -= block[0]
		block[1] = lcs64(block[1], 8)
	}

	return block
}

func kx_32_128(ink [4]uint32) (outk [27]uint32) {
	T := uint(27)
	m := uint(4)
	
	outk[0] = ink[0]

	for i := uint(0); i < (T-1); i++ {
		idx := 1 + i % (m-1)

		ink[idx] = rcs32(ink[idx], 8)
		ink[idx] += ink[0]
		ink[idx] ^= uint32(i)
		ink[0] = lcs32(ink[0], 3)
		ink[0] ^= ink[idx]		

		outk[i + 1] = ink[0]
	}

	return
}

func enc_32_128(block [2]uint32, kx [27]uint32) [2]uint32 {
	T := uint(27)

	for i := uint(0); i < T; i++ {
		block[1] = rcs32(block[1], 8)
		block[1] += block[0]
		block[1] ^= kx[i]
		block[0] = lcs32(block[0], 3)
		block[0] ^= block[1]		
	}

	return block
}

func dec_32_128(block [2]uint32, kx [27]uint32) [2]uint32 {
	T := uint(27)

	for i := T; i > 0; i-- {
		block[0] ^= block[1]
		block[0] = rcs32(block[0], 3)
		block[1] ^= kx[i-1]
		block[1] -= block[0]
		block[1] = lcs32(block[1], 8)
	}

	return block
}

func kx_16_64(ink [4]uint16) (outk [22]uint16) {
	T := uint(22)
	m := uint(4)
	
	outk[0] = ink[0]

	for i := uint(0); i < (T-1); i++ {
		idx := 1 + i % (m-1)

		ink[idx] = rcs16(ink[idx], 7)
		ink[idx] += ink[0]
		ink[idx] ^= uint16(i)
		ink[0] = lcs16(ink[0], 2)
		ink[0] ^= ink[idx]		

		outk[i + 1] = ink[0]
	}

	return
}

func enc_16_64(block [2]uint16, kx [22]uint16) [2]uint16 {
	T := uint(22)

	for i := uint(0); i < T; i++ {
		block[1] = rcs16(block[1], 7)
		block[1] += block[0]
		block[1] ^= kx[i]
		block[0] = lcs16(block[0], 2)
		block[0] ^= block[1]		
	}

	return block
}

func dec_16_64(block [2]uint16, kx [22]uint16) [2]uint16 {
	T := uint(22)

	for i := T; i > 0; i-- {
		block[0] ^= block[1]
		block[0] = rcs16(block[0], 2)
		block[1] ^= kx[i-1]
		block[1] -= block[0]
		block[1] = lcs16(block[1], 7)
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

type PrefixCipher struct {
	max uint
	enc []uint
	dec []uint
}

type ciphertext struct {
	raw []byte
	idx uint
}
type permutation []ciphertext

func (p permutation) Len() int { 
	return len(p) 
}
func (p permutation) Swap(i, j int) { 
	p[i], p[j] = p[j], p[i]
}
func (p permutation) Less(i, j int) bool { 
	if bytes.Compare(p[i].raw, p[j].raw) < 0 {
		return true
	} 
	return false
}

func NewPrefix(n uint, b cipher.Block) *PrefixCipher {
	p := PrefixCipher{
		max: n,
		enc: make([]uint, n),
		dec: make([]uint, n),
	}

	perm := make(permutation, 0)

	for i := uint(0); i < p.max; i++ { 
		inp := make([]byte, b.BlockSize())
		raw := make([]byte, b.BlockSize())
		
		binary.BigEndian.PutUint32(inp[0:], uint32(i))

		b.Encrypt(raw, inp)

		perm = append(perm, ciphertext{
			raw: raw,
			idx: i,
		})
	}

	sort.Sort(perm)
	
	for i := uint(0); i < p.max; i++ { 
		p.enc[perm[i].idx] = i
		p.dec[i] = perm[i].idx
	}

	return &p
}

func (p *PrefixCipher) Encrypt(plain uint) uint {
	return p.enc[plain]
}

func (p *PrefixCipher) Decrypt(cipher uint) uint {
	return p.dec[cipher]
}

func main() { 
	k := []byte("YELLOW SUBMARINE")
	b, _ := NewCipher(k, B64K128)
	pc := NewPrefix(10000, b)
	
	r := rand.New(rand.NewSource(99))

	for i := 0; i < 100; i++ { 
		v := r.Uint32() % 10000
		x := pc.Encrypt(uint(v))
		y := pc.Decrypt(x)
		fmt.Printf("in: %d out: %d recover: %d\n", v, x, y)
	}

}

