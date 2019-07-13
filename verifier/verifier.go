package verifier

type Verifier interface {
	GeneratePasswordHash(password string) (pwdHash string)
	CheckPasswordHash(pwHash, password string) (matched bool)
}
