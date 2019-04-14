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

	"github.com/jmoiron/sqlx"
	"github.com/ruchkinsa/pA01Server/api"
	"github.com/ruchkinsa/pA01Server/database"
)

type Config struct {
	ListenHost string
	API        api.Config
}

func Run(cfg *Config) error {
	log.Printf("Starting, HTTP on: %s\n", cfg.ListenHost)

	dbConnect, err := database.InitDb(cfg.API.DbConnect)
	if err != nil {
		log.Printf("Error initializing database: %v\n", err)
		return err
	}
	cfg.API.DbConnect.DbConn = dbConnect

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

	waitForSignal(dbConnect.DbConn)

	return nil
}

func waitForSignal(db *sqlx.DB) {
	ch := make(chan os.Signal)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	s := <-ch
	db.Close()
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
