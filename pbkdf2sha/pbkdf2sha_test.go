package pbkdf2sha

import (
	"testing"

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
