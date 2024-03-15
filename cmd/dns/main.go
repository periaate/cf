package main

import (
	"fmt"
	"log"
	"os"

	"github.com/periaate/cf/dns"
)

func main() {
	apiToken := os.Getenv("CF_API")
	zoneID := os.Getenv("CF_ZONE")
	domainName := os.Getenv("CF_DOMAIN")

	api, err := dns.InitCFAPI(apiToken)
	if err != nil {
		log.Fatalln("Failed to initialize Cloudflare API:", err)
	}

	if err := dns.EnsureDNS(api, zoneID, domainName); err != nil {
		log.Fatalln("error ensuring dns:", err)
	}

	fmt.Println("successfully updated DNS records")
}
