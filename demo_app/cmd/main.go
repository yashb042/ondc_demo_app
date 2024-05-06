package main

import (
	"context"
	"emperror.dev/errors"
	"github.com/gin-gonic/gin"
	"net/http"
	"ondc-buyer/demo_app"
	commonsApi "ondc-buyer/demo_app/apis"
	"ondc-buyer/demo_app/configs"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	env := "staging"
	demo_app.InitCommonsLibrary(demo_app.WithEnv(env), demo_app.WithAppName("Demo Yash App"))

	r := gin.New()
	commonsApi.InitiateOndcOnApis(r)
	commonsApi.InitiateSubscribeApi(r)

	done := make(chan os.Signal)
	signal.Notify(done, syscall.SIGINT, syscall.SIGTERM)

	port := configs.GlobalConfigs.App.HttpAddr
	server := &http.Server{
		Addr:    port,
		Handler: r,
	}
	go func() {
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			print("Error while starting the server")
		}
	}()

	<-done
	print("Server is shutting down")

	// The context is used to inform the server it has 1 second to finish
	// the request it is currently handling
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		print("Error while shutting down Server. Initiating force shutdown...", err)
	} else {
		print("Server exiting")
	}
}
