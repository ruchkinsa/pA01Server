package daemon

import (
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path"
	"syscall"

	"github.com/ruchkinsa/pA01Server/api"
)

type Config struct {
	ListenHost string
	API        api.Config
}

func Run(cfg *Config) error {
	log.Printf("Starting, HTTP on: %s\n", cfg.ListenHost)

	existsFile, err := exists(path.Join(cfg.API.PublicPath, cfg.API.NameFile))
	if !existsFile {
		if err != nil {
			log.Printf("Error initializing database: %v\n", err)
		}
		return errors.New(fmt.Sprintf("Database not found"))
	}

	listener, err := net.Listen("tcp", cfg.ListenHost)
	if err != nil {
		log.Printf("Error creating listener: %v\n", err)
		return err
	}

	api.Start(cfg.API, listener)

	waitForSignal()

	return nil
}

func waitForSignal() {
	ch := make(chan os.Signal)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	s := <-ch
	log.Printf("Got signal: %v, exiting.", s)
}

func exists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return true, err
}
