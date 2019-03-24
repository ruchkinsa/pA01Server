package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"path"

	//"path/filepath"

	"github.com/ruchkinsa/pA01Server/daemon"
)

var publicPath string

func main() {
	cfg := flagsRun()

	setupHttpAssets(cfg)

	if err := daemon.Run(cfg); err != nil {
		log.Printf("Error in main(): %v", err)
	}
}

func flagsRun() *daemon.Config {
	cfg := &daemon.Config{}

	flag.StringVar(&cfg.ListenHost, "listen", "localhost:10000", "HTTP listen")
	flag.StringVar(&publicPath, "public-path", "web", "Path to public dir")
	flag.StringVar(&cfg.API.DbConnect.ConnectString, "db-connect", "root:admin@tcp(localhost:3306)/licenses", "DB Connect String")
	flag.StringVar(&cfg.API.NameFile, "name-file", "keys.txt", "Test data")

	flag.Parse()
	return cfg
}

func setupHttpAssets(cfg *daemon.Config) {
	log.Printf("PublicPath served from %q.", publicPath)
	workDir, _ := os.Getwd()
	cfg.API.PublicPath = publicPath
	cfg.API.PublicPathCSS = http.Dir(path.Join(workDir, publicPath, "css"))
	cfg.API.PublicPathJS = http.Dir(path.Join(workDir, publicPath, "js"))
	cfg.API.PublicPathTemplates = http.Dir(path.Join(workDir, publicPath, "templates"))
}
