// Command pw-strength-query answers one question: how strong is this
// password? Pass it as an argument, or leave it off and type it at the
// prompt.
package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"pw-strength-query/strength"
)

func main() {
	password, err := readPassword(os.Args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	result := strength.Analyze(password)
	fmt.Printf("length:        %d\n", result.Length)
	fmt.Printf("charset size:  %d\n", result.PoolSize)
	fmt.Printf("entropy:       %.1f bits\n", result.Entropy)
	fmt.Printf("category:      %s\n", result.Category)
	fmt.Printf("online guess:  %s\n", strength.FormatSeconds(result.OnlineCrackSeconds))
	fmt.Printf("offline guess: %s\n", strength.FormatSeconds(result.OfflineCrackSeconds))
}

// readPassword takes the password from argv if given, otherwise prompts
// for it on stdin. This is the one place in the program that touches I/O;
// everything downstream of it is pure and doesn't need a terminal to test.
func readPassword(args []string) (string, error) {
	if len(args) > 1 {
		return args[1], nil
	}

	fmt.Print("password: ")
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	line = strings.TrimRight(line, "\r\n")
	if line == "" {
		if err != nil {
			return "", fmt.Errorf("no password given: %w", err)
		}
		return "", fmt.Errorf("no password given")
	}
	return line, nil
}
