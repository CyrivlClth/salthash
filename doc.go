// Package salthash provides a tool for generating password hashes compatible with the default encryption mode of the
// werkzueg package in python3.
//
// Example Usage
//
// The following is a complete example using in a password hash generate function:
//     import (
//       "fmt"
//
//       "github.com/CyrivlClth/salthash/pbkdf2sha"
//     )
//
//     func main() {
//       var password string = "123456abc"
//       var wrongPwd string = "123456bcd"
//       h := pbkdf2sha.New(0, 0)
//       pwdHash := h.GeneratePasswordHash(password)
//       fmt.Println(pwdHash)
//
//       fmt.Println(h.CheckPasswordHash(pwdHash, password))
//       fmt.Println(h.CheckPasswordHash(pwdHash, wrongPwd))
//     }
package salthash
