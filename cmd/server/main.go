package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"mui/internal/server"
)

func main() {
	if err := loadDotEnv(".env"); err != nil {
		log.Fatal(err)
	}
	if err := resolveSecretFiles(); err != nil {
		log.Fatal(err)
	}
	dsn, err := databaseDSN()
	if err != nil {
		log.Fatal(err)
	}
	store, err := server.NewStore(dsn, os.Getenv("MUI_SECRET"))
	if err != nil {
		log.Fatal(err)
	}
	defer store.DB.Close()
	publicURL := os.Getenv("MUI_PUBLIC_URL")
	if publicURL == "" {
		publicURL = "http://127.0.0.1:8080"
	}
	app, err := server.NewApp(store, publicURL)
	if err != nil {
		log.Fatal(err)
	}
	api := app.Handler()
	root := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/agent/") || strings.HasPrefix(r.URL.Path, "/download/") || strings.HasPrefix(r.URL.Path, "/s/") || r.URL.Path == "/healthz" {
			api.ServeHTTP(w, r)
			return
		}
		path := filepath.Join("web/dist", filepath.Clean("/"+r.URL.Path))
		// Files only: ServeFile would answer a directory with a listing.
		if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() {
			http.ServeFile(w, r, path)
			return
		}
		if filepath.Ext(r.URL.Path) != "" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		http.ServeFile(w, r, "web/dist/index.html")
	})
	address := os.Getenv("MUI_LISTEN")
	if address == "" {
		address = ":8080"
	}
	retention := 90
	if v := os.Getenv("MUI_TRAFFIC_RETENTION_DAYS"); v != "" {
		if retention, err = strconv.Atoi(v); err != nil || retention < 0 {
			log.Fatal("MUI_TRAFFIC_RETENTION_DAYS must be a non-negative number of days")
		}
	}
	// The dashboard's monthly figure is computed from raw samples.
	if retention > 0 && retention < 32 {
		retention = 32
	}
	if retention > 0 {
		go func() {
			for {
				if err := store.PruneTraffic(time.Now().AddDate(0, 0, -retention)); err != nil {
					log.Println("traffic pruning:", err)
				}
				if err := store.PruneAudit(time.Now().AddDate(0, 0, -retention)); err != nil {
					log.Println("audit pruning:", err)
				}
				time.Sleep(6 * time.Hour)
			}
		}()
	}
	// Unconfirmed upgrades must not wait for an administrator to open the
	// operations page: expire them in the background.
	go func() {
		for {
			if err := store.ExpireUpgrades(); err != nil {
				log.Println("expire upgrades:", err)
			}
			time.Sleep(time.Minute)
		}
	}()
	// Certificate expiry alerts, on the pruning schedule.
	go func() {
		for {
			app.CheckExpiringCertificates()
			time.Sleep(6 * time.Hour)
		}
	}()
	serverHTTP := &http.Server{Addr: address, Handler: app.SecurityHeaders(root), ReadHeaderTimeout: 10 * time.Second,
		// Request bodies are small JSON documents. There is deliberately no write
		// timeout: agents download a 100 MB core over whatever link they have.
		ReadTimeout: time.Minute, IdleTimeout: 2 * time.Minute}
	cert, key := os.Getenv("MUI_TLS_CERT"), os.Getenv("MUI_TLS_KEY")
	if (cert == "") != (key == "") {
		log.Fatal("MUI_TLS_CERT and MUI_TLS_KEY must be set together")
	}
	if cert != "" {
		fmt.Println("mui listening with TLS on", address)
		log.Fatal(serverHTTP.ListenAndServeTLS(cert, key))
	}
	fmt.Println("mui listening on", address, "(plain HTTP; put a TLS-terminating proxy in front)")
	log.Fatal(serverHTTP.ListenAndServe())
}
