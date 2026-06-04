package main

import (
	"crypto"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/google/uuid"
)

type signCloser interface {
	crypto.Signer
	Close() error
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "create":
		runCreate(os.Args[2:])
	case "delete":
		runDelete(os.Args[2:])
	case "certtest":
		runCertTestCmd(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `usage: %s <command> [flags]

commands:
  create   [-name NAME]   create a TPM-backed key (random uuid name if omitted)
  delete   -name NAME     delete a TPM-backed key by name
  certtest                create a throwaway key, build a root+leaf certificate,
                          verify them against each other, then delete the key
`, os.Args[0])
}

func runCreate(args []string) {
	fs := flag.NewFlagSet("create", flag.ExitOnError)
	name := fs.String("name", "", "key name (defaults to a random uuid)")
	fs.Parse(args)

	if *name == "" {
		*name = uuid.NewString()
	}

	signer, err := createKey(*name)
	if err != nil {
		log.Fatalf("create key: %v", err)
	}
	defer signer.Close()

	log.Printf("created key %q", *name)
}

func runDelete(args []string) {
	fs := flag.NewFlagSet("delete", flag.ExitOnError)
	name := fs.String("name", "", "key name to delete (required)")
	fs.Parse(args)

	if *name == "" {
		log.Fatal("delete: -name is required")
	}

	if err := deleteKey(*name); err != nil {
		log.Fatalf("delete key: %v", err)
	}

	log.Printf("deleted key %q", *name)
}

func runCertTestCmd(args []string) {
	fs := flag.NewFlagSet("certtest", flag.ExitOnError)
	fs.Parse(args)

	name := uuid.NewString()
	signer, err := createKey(name)
	if err != nil {
		log.Fatalf("create key: %v", err)
	}

	defer func() {
		signer.Close()
		if err := deleteKey(name); err != nil {
			log.Printf("warning: delete throwaway key %q: %v", name, err)
		}
	}()

	log.Printf("created throwaway key %q", name)

	if err := runCertTest(signer); err != nil {
		log.Fatalf("certtest: %v", err)
	}

	log.Print("certtest: root and leaf certificates verified successfully")
}
