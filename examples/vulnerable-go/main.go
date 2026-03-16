package main

import (
	"crypto/md5"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
)

// G101: Hardcoded credentials
const apiKey = "sk-1234567890abcdef"
const password = "SuperSecret123!"

func main() {
	// G401: Weak cryptographic hash (MD5)
	hash := md5.New()
	hash.Write([]byte("sensitive data"))
	fmt.Printf("Hash: %x\n", hash.Sum(nil))

	// G404: Weak random number generator
	randomNum := rand.Int()
	fmt.Printf("Random: %d\n", randomNum)

	// G204: Command injection vulnerability
	userInput := os.Args[1]
	cmd := exec.Command("sh", "-c", userInput)
	cmd.Run()

	// G304: Path traversal vulnerability
	filename := os.Args[2]
	data, _ := os.ReadFile(filename)
	fmt.Println(string(data))

	// G302: Insecure file permissions
	os.Chmod("/tmp/secret.txt", 0777)
}
