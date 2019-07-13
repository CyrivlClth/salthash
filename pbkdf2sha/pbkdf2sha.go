package pbkdf2sha

import (
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"math/rand"
	"strconv"
	"strings"
	"time"

	"github.com/CyrivlClth/salthash/verifier"
	"golang.org/x/crypto/pbkdf2"
)

type digest struct {
	saltLen  int
	iter     int
	saltFunc func(int) []byte
}

func (d *digest) GeneratePasswordHash(password string) (pwdHash string) {
	salt := d.salt()
	hashStr := pbkdf2Algorithm([]byte(password), salt, d.iter, 32, sha256.New)
	return d.pbkdf2Str(salt, hashStr)
}

func (d *digest) CheckPasswordHash(pwHash, password string) (matched bool) {
	args := strings.Split(pwHash, "$")
	if len(args) < 3 {
		return false
	}
	if !strings.HasPrefix(args[0], "pbkdf2:sha256") {
		return false
	}
	title := strings.Split(args[0], ":")
	if len(title) < 3 {
		return false
	}
	iter, err := strconv.Atoi(title[2])
	if err != nil || iter <= 0 {
		return false
	}
	checkStr := pbkdf2Algorithm([]byte(password), []byte(args[1]), iter, 32, sha256.New)
	return checkStr == args[2]
}

func (d *digest) pbkdf2Str(salt []byte, hashStr string) string {
	return "pbkdf2:sha256:" + strconv.FormatInt(int64(d.iter), 10) + "$" + string(salt) + "$" + hashStr
}

func (d *digest) salt() []byte {
	return d.saltFunc(d.saltLen)
}

func pbkdf2Algorithm(str, salt []byte, iter, keyLen int, h func() hash.Hash) string {
	dk := pbkdf2.Key(str, salt, iter, keyLen, h)
	return hex.EncodeToString(dk)
}

func New(saltLen, iter int) verifier.Verifier {
	if saltLen <= 0 || saltLen > 8 {
		saltLen = 8
	}
	if iter <= 0 || iter > 100000 {
		iter = 15000
	}
	return &digest{
		saltLen:  saltLen,
		iter:     iter,
		saltFunc: GetRandomString,
	}
}

// 生成随机字符串
func GetRandomString(length int) []byte {
	str := "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	bytes := []byte(str)
	var result []byte
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	for i := 0; i < length; i++ {
		result = append(result, bytes[r.Intn(len(bytes))])
	}
	return result
}
