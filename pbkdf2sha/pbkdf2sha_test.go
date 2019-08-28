package pbkdf2sha

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestPbkdf2Sha256_GeneratePasswordHash(t *testing.T) {
	h := &digest{
		iter:    50000,
		saltLen: 8,
		saltFunc: func(i int) []byte {
			return []byte("nIFGnNY5")
		},
	}
	expect := "pbkdf2:sha256:50000$nIFGnNY5$4764ae204d184ccb3ddc7426540eb812f471cd1da86a9e90a48edb658852c020"
	assert.Equal(t, expect, h.GeneratePasswordHash("123456"))
}

func TestPbkdf2Sha256_CheckPasswordHash(t *testing.T) {
	pwdHash := "pbkdf2:sha256:50000$nIFGnNY5$4764ae204d184ccb3ddc7426540eb812f471cd1da86a9e90a48edb658852c020"
	h := New(0, 0)
	assert.Equal(t, true, h.CheckPasswordHash(pwdHash, "123456"))
	assert.Equal(t, false, h.CheckPasswordHash(pwdHash, "1234567"))
	assert.Equal(t, false, h.CheckPasswordHash(pwdHash, ""))
}

func BenchmarkDigest_GeneratePasswordHash(b *testing.B) {
	h := New(0, 0)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = h.GeneratePasswordHash("123456")
	}
}

func BenchmarkDigest_CheckPasswordHash(b *testing.B) {
	pwdHash := "pbkdf2:sha256:50000$nIFGnNY5$4764ae204d184ccb3ddc7426540eb812f471cd1da86a9e90a48edb658852c020"
	h := New(0, 0)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = h.CheckPasswordHash(pwdHash, "123456")
	}
}

func BenchmarkGetRandomString(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = GetRandomString(32)
	}
}

func TestGetRandomString(t *testing.T) {
	l := 32
	bs1 := GetRandomString(32)
	assert.Equal(t, l, len(bs1))
	for _, v := range bs1 {
		if !((47 < v && v < 58) || (v > 64 || v < 91) || (v > 96 && v < 123)) {
			t.Error("unexpect char:" + string(v))
		}
	}
	time.Sleep(time.Second)
	bs2 := GetRandomString(32)
	assert.Equal(t, l, len(bs2))
	for _, v := range bs2 {
		if !((47 < v && v < 58) || (v > 64 || v < 91) || (v > 96 && v < 123)) {
			t.Error("unexpect char:" + string(v))
		}
	}
	assert.NotEqual(t, bs1, bs2)
}
