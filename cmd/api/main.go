// Command api menjalankan server My Auth Go.
//
// Satu binary: migrasi database, seeder admin, server HTTP, dan dokumentasi
// Swagger. Konfigurasi dari environment / .env.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	_ "github.com/sekolah-alazhar/my-auth-go/docs" // hasil swag init

	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"

	"github.com/sekolah-alazhar/my-auth-go/config"
	"github.com/sekolah-alazhar/my-auth-go/routes"
)

// version diisi lewat ldflags saat build rilis.
var version = "dev"

func main() {
	var (
		showVersion = flag.Bool("version", false, "tampilkan versi lalu keluar")
		seedOnly    = flag.Bool("seed", false, "jalankan migrasi + seeder lalu keluar")
		noSwagger   = flag.Bool("no-swagger", false, "matikan rute /swagger/*")
	)
	flag.Parse()

	if *showVersion {
		fmt.Println("my-auth-go", version)
		return
	}

	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(log)

	cfg, err := config.Load()
	if err != nil {
		log.Error("konfigurasi tidak valid", "err", err)
		os.Exit(1)
	}
	cfg.Version = version

	db, err := config.Connect(cfg, log)
	if err != nil {
		log.Error("koneksi database gagal", "err", err, "dsn", cfg.RedactedDSN())
		os.Exit(1)
	}
	defer config.Close()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := config.Migrate(ctx, db, log); err != nil {
		log.Error("migrasi gagal", "err", err)
		os.Exit(1)
	}

	res, err := config.Seed(ctx, db, cfg, log)
	if err != nil {
		log.Error("seeder gagal", "err", err)
		os.Exit(1)
	}

	if *seedOnly {
		log.Info("migrasi + seeder selesai", "admin_dibuat", res.Created, "dilewati", res.Skipped)
		return
	}

	if !cfg.IsProduction() {
		gin.SetMode(gin.DebugMode)
	}

	router := routes.New(routes.Options{
		Config:           cfg,
		DB:               db,
		Log:              log,
		Version:          version,
		ExposeResetToken: !cfg.IsProduction(),
	})

	// Swagger hanya di lingkungan non-produksi, atau bila diminta eksplisit.
	if !*noSwagger && !cfg.IsProduction() {
		router.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))
		log.Info("swagger aktif", "url", cfg.PublicBaseURL+"/swagger/index.html")
	}

	srv := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           router,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20, // 1 MiB
	}

	go func() {
		log.Info("server berjalan",
			"port", cfg.Port,
			"env", cfg.Env,
			"version", version,
			"db", cfg.RedactedDSN(),
		)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("server berhenti", "err", err)
			os.Exit(1)
		}
	}()

	<-ctx.Done()
	log.Info("sinyal berhenti diterima, shutdown...")

	shCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := srv.Shutdown(shCtx); err != nil {
		log.Error("shutdown tidak bersih", "err", err)
	} else {
		log.Info("shutdown selesai")
	}
}
