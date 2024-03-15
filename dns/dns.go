package dns

import (
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/cloudflare/cloudflare-go"
)

// Fetches the current external IP address
func GetCurrentIP() (string, error) {
	resp, err := http.Get("https://api.ipify.org")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	ip, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(ip), nil
}

// InitCFAPI intializes Cloudflare API with the given API token
func InitCFAPI(apiToken string) (*cloudflare.API, error) {
	api, err := cloudflare.NewWithAPIToken(apiToken)
	if err != nil {
		fmt.Println("Error initializing Cloudflare API:", err)
		return nil, err
	}
	return api, nil
}

// GetDomainARecords fetches all A records for a given domain.
func GetDomainARecords(api *cloudflare.API, zoneID, domainName string) (records []cloudflare.DNSRecord, err error) {
	records, _, err = api.ListDNSRecords(context.Background(),
		cloudflare.ZoneIdentifier(zoneID),
		cloudflare.ListDNSRecordsParams{Type: "A", Name: domainName},
	)
	if err != nil {
		err = fmt.Errorf("error fetching DNS records: %w", err)
		return
	}

	if len(records) == 0 {
		err = fmt.Errorf("no A records found for domain: %s", domainName)
		return
	}
	return records, nil
}

// EnsureDNS updates the A record if it does not point to the current IP address
func EnsureDNS(api *cloudflare.API, zoneID, domainName string) error {
	currentIP, err := GetCurrentIP()
	if err != nil {
		return err
	}
	fmt.Println("Current IP:", currentIP)

	records, _, err := api.ListDNSRecords(context.Background(),
		cloudflare.ZoneIdentifier(zoneID),
		cloudflare.ListDNSRecordsParams{Type: "A", Name: domainName},
	)
	if err != nil {
		return err
	}

	for _, record := range records {
		if record.Content != currentIP {
			_, err := api.UpdateDNSRecord(
				context.Background(),
				cloudflare.ZoneIdentifier(zoneID),
				cloudflare.UpdateDNSRecordParams{
					ID:      record.ID,
					Type:    "A",
					Name:    domainName,
					Content: currentIP,
				})
			if err != nil {
				return err
			}
			fmt.Println("Updated DNS A record for", domainName, "to point to", currentIP)
			return nil
		} else {
			fmt.Println("No update required for", domainName, "- already points to", currentIP)
			return nil
		}
	}
	return nil
}
