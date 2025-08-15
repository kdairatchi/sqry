package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
)

// runHTTPX executes the httpx binary on the given results and
// enriches them with page title and screenshot path.
func runHTTPX(results []Result) error {
	if len(results) == 0 {
		return nil
	}
	if _, err := exec.LookPath("httpx"); err != nil {
		return fmt.Errorf("httpx binary not found")
	}
	cmd := exec.Command("httpx", "-silent", "-json", "-title", "-screenshot", "-threads", "50")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() {
		for _, r := range results {
			fmt.Fprintln(stdin, r.IP)
		}
		stdin.Close()
	}()

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		var out struct {
			Host       string `json:"host"`
			Title      string `json:"title"`
			Screenshot string `json:"screenshot"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &out); err != nil {
			continue
		}
		host := out.Host
		host = strings.TrimPrefix(host, "http://")
		host = strings.TrimPrefix(host, "https://")
		host = strings.Split(host, "/")[0]
		for i := range results {
			if results[i].IP == host {
				results[i].Title = out.Title
				results[i].Screenshot = out.Screenshot
				break
			}
		}
	}
	return cmd.Wait()
}
