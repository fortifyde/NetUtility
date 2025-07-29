package main

import (
	"fmt"
	"os"
	"strings"

	"netutil/internal/oui"
)

// ouihelper is a command-line utility for MAC address vendor lookups
// It's designed to be called from shell scripts for fast OUI database access
func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <command> [args...]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Commands:\n")
		fmt.Fprintf(os.Stderr, "  lookup <mac>     Look up vendor for MAC address\n")
		fmt.Fprintf(os.Stderr, "  info             Show database information\n")
		fmt.Fprintf(os.Stderr, "  format <mac>     Format MAC address\n")
		fmt.Fprintf(os.Stderr, "  check <mac>      Check MAC address properties\n")
		os.Exit(1)
	}

	command := strings.ToLower(os.Args[1])

	switch command {
	case "lookup":
		if len(os.Args) < 3 {
			fmt.Fprintf(os.Stderr, "Usage: %s lookup <mac_address>\n", os.Args[0])
			os.Exit(1)
		}
		lookupVendor(os.Args[2])

	case "info":
		showDatabaseInfo()

	case "format":
		if len(os.Args) < 3 {
			fmt.Fprintf(os.Stderr, "Usage: %s format <mac_address>\n", os.Args[0])
			os.Exit(1)
		}
		formatMAC(os.Args[2])

	case "check":
		if len(os.Args) < 3 {
			fmt.Fprintf(os.Stderr, "Usage: %s check <mac_address>\n", os.Args[0])
			os.Exit(1)
		}
		checkMAC(os.Args[2])

	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", command)
		os.Exit(1)
	}
}

// lookupVendor looks up the vendor for a MAC address
func lookupVendor(macAddress string) {
	vendor, err := oui.LookupMAC(macAddress)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(vendor)
}

// showDatabaseInfo displays information about the OUI database
func showDatabaseInfo() {
	info, err := oui.GetDatabaseInfo()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("OUI Database Information:\n")
	fmt.Printf("  Total Entries: %d\n", info.TotalEntries)
	fmt.Printf("  Last Update: %s\n", info.LastUpdate.Format("2006-01-02 15:04:05"))
	fmt.Printf("  Source: %s\n", info.Source)
	fmt.Printf("  Version: %s\n", info.Version)
}

// formatMAC formats a MAC address in standard notation
func formatMAC(macAddress string) {
	formatted := oui.FormatMACAddress(macAddress)
	fmt.Println(formatted)
}

// checkMAC checks various properties of a MAC address
func checkMAC(macAddress string) {
	vendor, _ := oui.LookupMAC(macAddress)
	formatted := oui.FormatMACAddress(macAddress)
	ouiPrefix := oui.ExtractOUI(macAddress)
	isLocallyAdmin := oui.IsLocallyAdministered(macAddress)
	isMulticast := oui.IsMulticast(macAddress)
	isBroadcast := oui.IsBroadcast(macAddress)

	fmt.Printf("MAC Address Analysis:\n")
	fmt.Printf("  Original: %s\n", macAddress)
	fmt.Printf("  Formatted: %s\n", formatted)
	fmt.Printf("  OUI: %s\n", ouiPrefix)
	fmt.Printf("  Vendor: %s\n", vendor)
	fmt.Printf("  Locally Administered: %t\n", isLocallyAdmin)
	fmt.Printf("  Multicast: %t\n", isMulticast)
	fmt.Printf("  Broadcast: %t\n", isBroadcast)
}
