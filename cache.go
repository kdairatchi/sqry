package main

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type CacheEntry struct {
	Data      interface{} `json:"data"`
	Timestamp int64       `json:"timestamp"`
	TTL       int64       `json:"ttl"` // TTL in seconds
}

func getCacheDir() string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		// Fallback to temp directory if can't get home dir
		tempDir := os.TempDir()
		cacheDir := filepath.Join(tempDir, "sqry-cache")
		if err := os.MkdirAll(cacheDir, 0755); err != nil {
			return tempDir // Last resort - use temp dir directly
		}
		return cacheDir
	}
	cacheDir := filepath.Join(homeDir, ".sqry", "cache")
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		// If can't create in home dir, fall back to temp
		tempDir := os.TempDir()
		fallbackDir := filepath.Join(tempDir, "sqry-cache")
		os.MkdirAll(fallbackDir, 0755)
		return fallbackDir
	}
	return cacheDir
}

func getCacheKey(query string) string {
	h := md5.Sum([]byte(query))
	return fmt.Sprintf("%x", h)
}

func getCacheFile(key string) string {
	return filepath.Join(getCacheDir(), key+".json")
}

func cacheGet(key string) (interface{}, bool) {
	file := getCacheFile(key)
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, false
	}

	var entry CacheEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		// If cache file is corrupted, remove it
		os.Remove(file)
		return nil, false
	}

	// Check if cache is expired
	if time.Now().Unix()-entry.Timestamp > entry.TTL {
		os.Remove(file) // Clean up expired cache
		return nil, false
	}

	return entry.Data, true
}

func cacheSet(key string, data interface{}, ttlSeconds int64) error {
	file := getCacheFile(key)
	entry := CacheEntry{
		Data:      data,
		Timestamp: time.Now().Unix(),
		TTL:       ttlSeconds,
	}

	jsonData, err := json.Marshal(entry)
	if err != nil {
		return err
	}

	// Write atomically to avoid corruption
	tempFile := file + ".tmp"
	if err := os.WriteFile(tempFile, jsonData, 0644); err != nil {
		return err
	}
	return os.Rename(tempFile, file)
}

func clearExpiredCache() {
	cacheDir := getCacheDir()
	entries, err := os.ReadDir(cacheDir)
	if err != nil {
		return
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		
		// Only process .json cache files
		if !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		
		filePath := filepath.Join(cacheDir, entry.Name())
		data, err := os.ReadFile(filePath)
		if err != nil {
			// If can't read file, it might be corrupted - remove it
			os.Remove(filePath)
			continue
		}

		var cacheEntry CacheEntry
		if err := json.Unmarshal(data, &cacheEntry); err != nil {
			// If can't parse JSON, it's corrupted - remove it
			os.Remove(filePath)
			continue
		}

		// Remove expired entries
		if time.Now().Unix()-cacheEntry.Timestamp > cacheEntry.TTL {
			os.Remove(filePath)
		}
	}
}