package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/ckanthony/openapi-mcp/pkg/config"
	"github.com/ckanthony/openapi-mcp/pkg/parser"
	"github.com/ckanthony/openapi-mcp/pkg/server"
	"github.com/joho/godotenv"
)

// stringSliceFlag allows defining a flag that can be repeated to collect multiple string values.
type stringSliceFlag []string

func (i *stringSliceFlag) String() string {
	return strings.Join(*i, ", ")
}

func (i *stringSliceFlag) Set(value string) error {
	*i = append(*i, value)
	return nil
}

func main() {
	// --- Flag Definitions First ---
	// Define specPath early so we can use it for .env loading
	specPath := flag.String("spec", "", "Path or URL to the OpenAPI specification file (required)")
	port := flag.Int("port", 8080, "Port to run the MCP server on")

	apiKey := flag.String("api-key", "", "Direct API key value")
	apiKeyEnv := flag.String("api-key-env", "", "Environment variable name containing the API key")
	apiKeyName := flag.String("api-key-name", "", "Name of the API key header, query parameter, path parameter, or cookie (required if api-key or api-key-env is set)")
	apiKeyLocStr := flag.String("api-key-loc", "", "Location of API key: 'header', 'query', 'path', or 'cookie' (required if api-key or api-key-env is set)")

	var includeTags stringSliceFlag
	flag.Var(&includeTags, "include-tag", "Tag to include (can be repeated)")
	var excludeTags stringSliceFlag
	flag.Var(&excludeTags, "exclude-tag", "Tag to exclude (can be repeated)")
	var includeOps stringSliceFlag
	flag.Var(&includeOps, "include-op", "Operation ID to include (can be repeated)")
	var excludeOps stringSliceFlag
    flag.Var(&excludeOps, "exclude-op", "Operation ID to exclude (can be repeated)")
    var setBody stringSliceFlag
    flag.Var(&setBody, "set-body", "Key-value pair to set in the request body (e.g., 'user.name=ooxx')")

    serverBaseURL := flag.String("base-url", "", "Manually override the server base URL")
    defaultToolName := flag.String("name", "OpenAPI-MCP Tools", "Default name for the toolset")
	defaultToolDesc := flag.String("desc", "Tools generated from OpenAPI spec", "Default description for the toolset")

	// Parse flags *after* defining them all
	flag.Parse()

	// --- Load .env after parsing flags ---
	if *specPath != "" && !strings.HasPrefix(*specPath, "http://") && !strings.HasPrefix(*specPath, "https://") {
		envPath := filepath.Join(filepath.Dir(*specPath), ".env")
		log.Printf("Attempting to load .env file from spec directory: %s", envPath)
		err := godotenv.Load(envPath)
		if err != nil {
			// It's okay if the file doesn't exist, log other errors.
			if !os.IsNotExist(err) {
				log.Printf("Warning: Error loading .env file from %s: %v", envPath, err)
			} else {
				log.Printf("Info: No .env file found at %s, proceeding without it.", envPath)
			}
		} else {
			log.Printf("Successfully loaded .env file from %s", envPath)
		}
	} else if *specPath == "" {
		log.Println("Skipping .env load because --spec is missing.")
	} else {
		log.Println("Skipping .env load because spec path appears to be a URL.")
	}

	// --- Read REQUEST_HEADERS env var ---
	customHeadersEnv := os.Getenv("REQUEST_HEADERS")
	if customHeadersEnv != "" {
		log.Printf("Found REQUEST_HEADERS environment variable: %s", customHeadersEnv)
	}

	// --- Input Validation ---
	if *specPath == "" {
		log.Println("Error: --spec flag is required.")
		flag.Usage()
		os.Exit(1)
	}

	var apiKeyLocation config.APIKeyLocation
	if *apiKeyLocStr != "" {
		switch *apiKeyLocStr {
		case string(config.APIKeyLocationHeader):
			apiKeyLocation = config.APIKeyLocationHeader
		case string(config.APIKeyLocationQuery):
			apiKeyLocation = config.APIKeyLocationQuery
		case string(config.APIKeyLocationPath):
			apiKeyLocation = config.APIKeyLocationPath
		case string(config.APIKeyLocationCookie):
			apiKeyLocation = config.APIKeyLocationCookie
		default:
			log.Fatalf("Error: invalid --api-key-loc value: %s. Must be 'header', 'query', 'path', or 'cookie'.", *apiKeyLocStr)
		}
	}

	// --- Configuration Population ---
	cfg := &config.Config{
		SpecPath:          *specPath,
		APIKey:            *apiKey,
		APIKeyFromEnvVar:  *apiKeyEnv,
		APIKeyName:        *apiKeyName,
		APIKeyLocation:    apiKeyLocation,
		IncludeTags:       includeTags,
		ExcludeTags:       excludeTags,
		IncludeOperations: includeOps,
		ExcludeOperations: excludeOps,
		ServerBaseURL:     *serverBaseURL,
		DefaultToolName:   *defaultToolName,
		DefaultToolDesc:   *defaultToolDesc,
		CustomHeaders:     customHeadersEnv,
		SetBody:           setBody,
	}

	log.Printf("Configuration loaded: %+v\n", cfg)
	log.Println("API Key (resolved):", cfg.GetAPIKey())

	// --- Call Parser ---
	specDoc, version, err := parser.LoadSwagger(cfg.SpecPath)
	if err != nil {
		log.Fatalf("Failed to load OpenAPI/Swagger spec: %v", err)
	}
	log.Printf("Spec type %s loaded successfully from %s.\n", version, cfg.SpecPath)

	toolSet, err := parser.GenerateToolSet(specDoc, version, cfg)
	if err != nil {
		log.Fatalf("Failed to generate MCP toolset: %v", err)
	}
	log.Printf("MCP toolset generated with %d tools.\n", len(toolSet.Tools))

	// --- Start Server ---
	addr := fmt.Sprintf(":%d", *port)
	log.Printf("Starting MCP server on %s...", addr)
	err = server.ServeMCP(addr, toolSet, cfg) // Pass cfg to ServeMCP
	if err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
