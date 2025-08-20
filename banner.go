package main

import (
	"fmt"
	"os"
	"strings"
	"time"
)

const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
	ColorPurple = "\033[35m"
	ColorCyan   = "\033[36m"
	ColorWhite  = "\033[37m"
	ColorBold   = "\033[1m"
	ColorDim    = "\033[2m"
)

func printBanner() {
	if !isTerminal() {
		return // Skip banner for non-terminal output
	}
	// Check if colors should be disabled (can be passed as parameter later)
	noColor := os.Getenv("NO_COLOR") != ""

	if noColor {
		banner := `
   ███████╗ ██████╗ ██████╗ ██╗   ██╗
   ██╔════╝██╔═══██╗██╔══██╗╚██╗ ██╔╝
   ███████╗██║   ██║██████╔╝ ╚████╔╝ 
   ╚════██║██║▄▄ ██║██╔══██╗  ╚██╔╝  
   ███████║╚██████╔╝██║  ██║   ██║   
   ╚══════╝ ╚══▀▀═╝ ╚═╝  ╚═╝   ╚═╝   
┌─────────────────────────────────────┐
│  Advanced Shodan Intelligence Tool  │  
│     CVE Integration • Fast • CLI    │
└─────────────────────────────────────┘

v1.2.1-fixed • Made with ❤️ by @kdairatchi
https://github.com/kdairatchi/sqry

`
		fmt.Fprint(os.Stderr, banner)
	} else {
		banner := fmt.Sprintf(`%s%s
   ███████╗ ██████╗ ██████╗ ██╗   ██╗
   ██╔════╝██╔═══██╗██╔══██╗╚██╗ ██╔╝
   ███████╗██║   ██║██████╔╝ ╚████╔╝ 
   ╚════██║██║▄▄ ██║██╔══██╗  ╚██╔╝  
   ███████║╚██████╔╝██║  ██║   ██║   
   ╚══════╝ ╚══▀▀═╝ ╚═╝  ╚═╝   ╚═╝   %s
%s┌─────────────────────────────────────┐%s
%s│%s  Advanced Shodan Intelligence Tool  %s│%s  
%s│%s     CVE Integration • Fast • CLI    %s│%s
%s└─────────────────────────────────────┘%s

%s%sv1.2.1-fixed%s • Made with %s❤️%s by %s@kdairatchi%s
%s%shttps://github.com/kdairatchi/sqry%s

`,
			ColorBold, ColorCyan, ColorReset,
			ColorBlue, ColorReset,
			ColorBlue, ColorWhite, ColorBlue, ColorReset,
			ColorBlue, ColorGreen, ColorBlue, ColorReset,
			ColorBlue, ColorReset,
			ColorDim, ColorYellow, ColorReset, ColorRed, ColorReset, ColorPurple, ColorReset,
			ColorDim, ColorCyan, ColorReset,
		)
		fmt.Fprint(os.Stderr, banner)
	}
}

func printSuccess(message string) {
	if !isTerminal() {
		return
	}
	fmt.Fprintf(os.Stderr, "%s[✓]%s %s\n", ColorGreen, ColorReset, message)
}

func printInfo(message string) {
	if !isTerminal() {
		return
	}
	fmt.Fprintf(os.Stderr, "%s[i]%s %s\n", ColorBlue, ColorReset, message)
}

func printWarning(message string) {
	if !isTerminal() {
		return
	}
	fmt.Fprintf(os.Stderr, "%s[!]%s %s\n", ColorYellow, ColorReset, message)
}

func printError(message string) {
	if !isTerminal() {
		return
	}
	fmt.Fprintf(os.Stderr, "%s[✗]%s %s\n", ColorRed, ColorReset, message)
}

func printStats(ips int, duration time.Duration) {
	if !isTerminal() {
		return
	}
	fmt.Fprintf(os.Stderr, "%s[📊]%s Found %s%d%s unique IPs in %s%v%s\n\n", 
		ColorCyan, ColorReset, ColorBold, ips, ColorReset, ColorGreen, duration.Round(time.Millisecond), ColorReset)
}

func isTerminal() bool {
	// Simple check if we're outputting to terminal
	stat, err := os.Stderr.Stat()
	if err != nil {
		return false
	}
	return (stat.Mode() & os.ModeCharDevice) != 0
}

func formatTable(headers []string, rows [][]string) string {
	if len(rows) == 0 {
		return ""
	}

	// Calculate column widths
	colWidths := make([]int, len(headers))
	for i, header := range headers {
		colWidths[i] = len(header)
	}
	
	for _, row := range rows {
		for i, cell := range row {
			if i < len(colWidths) && len(cell) > colWidths[i] {
				colWidths[i] = len(cell)
			}
		}
	}

	var sb strings.Builder
	
	// Print header
	sb.WriteString(ColorBold)
	for i, header := range headers {
		sb.WriteString(fmt.Sprintf("%-*s", colWidths[i]+2, header))
	}
	sb.WriteString(ColorReset + "\n")
	
	// Print separator
	sb.WriteString(ColorDim)
	for i := range headers {
		sb.WriteString(strings.Repeat("─", colWidths[i]+2))
	}
	sb.WriteString(ColorReset + "\n")
	
	// Print rows
	for _, row := range rows {
		for i, cell := range row {
			if i < len(colWidths) {
				sb.WriteString(fmt.Sprintf("%-*s", colWidths[i]+2, cell))
			}
		}
		sb.WriteString("\n")
	}
	
	return sb.String()
}