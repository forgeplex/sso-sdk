package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	sso "github.com/forgeplex/sso-sdk"
)

func main() {
	client, err := sso.New(sso.Config{
		IssuerURL:     requiredEnv("SSO_ISSUER"),
		ManagementURL: strings.TrimSpace(os.Getenv("SSO_MANAGEMENT_URL")),
		Audience:      requiredEnv("SSO_AUDIENCE"),
		RealmID:       requiredEnv("SSO_REALM_ID"),
		ClientID:      requiredEnv("SSO_CLIENT_ID"),
		ClientSecret:  requiredEnv("SSO_CLIENT_SECRET"),
		Scopes:        []string{"read:clients"},
	})
	if err != nil {
		log.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	page, err := client.Applications.List(ctx, sso.ListOptions{PerPage: 20})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("共 %d 个应用\n", page.Total)
	for _, application := range page.Items {
		fmt.Printf("- %s (%s)\n", application.Name, application.ClientID)
	}
}

func requiredEnv(name string) string {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		log.Fatalf("缺少环境变量 %s", name)
	}
	return value
}
