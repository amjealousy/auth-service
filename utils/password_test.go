package utils

import (
	"fmt"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestCreateHashBcrypt(t *testing.T) {

	input := "ks06032001"
	hpassword, err := bcrypt.GenerateFromPassword([]byte(input), bcrypt.DefaultCost)
	if err != nil {
		return
	}
	fmt.Println("hpassword:", string(hpassword))
}
