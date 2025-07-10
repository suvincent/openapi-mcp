package parser

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/go-openapi/spec"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ckanthony/openapi-mcp/pkg/config"
	"github.com/ckanthony/openapi-mcp/pkg/mcp"
)

// Minimal valid OpenAPI V3 spec (JSON string)
const minimalV3SpecJSON = `{
  "openapi": "3.0.0",
  "info": {
    "title": "Minimal V3 API",
    "version": "1.0.0"
  },
  "paths": {
    "/ping": {
      "get": {
        "summary": "Simple ping endpoint",
        "operationId": "getPing",
        "responses": {
          "200": {
            "description": "OK"
          }
        }
      }
    }
  }
}`

// Minimal valid Swagger V2 spec (JSON string)
const minimalV2SpecJSON = `{
  "swagger": "2.0",
  "info": {
    "title": "Minimal V2 API",
    "version": "1.0.0"
  },
  "paths": {
    "/health": {
      "get": {
        "summary": "Simple health check",
        "operationId": "getHealth",
        "produces": ["application/json"],
        "responses": {
          "200": {
            "description": "OK"
          }
        }
      }
    }
  }
}`

// Malformed JSON
const malformedJSON = `{
  "openapi": "3.0.0",
  "info": {
    "title": "Missing Version",
  }
}`

// JSON without version key
const noVersionKeyJSON = `{
  "info": {
    "title": "No Version Key",
    "version": "1.0"
  },
  "paths": {}
}`

// V3 Spec with tags and multiple operations
const complexV3SpecJSON = `{
  "openapi": "3.0.0",
  "info": {
    "title": "Complex V3 API",
    "version": "1.1.0"
  },
  "tags": [
    {"name": "tag1", "description": "First Tag"},
    {"name": "tag2", "description": "Second Tag"}
  ],
  "paths": {
    "/items": {
      "get": {
        "summary": "List Items",
        "operationId": "listItems",
        "tags": ["tag1"],
        "responses": {"200": {"description": "OK"}}
      },
      "post": {
        "summary": "Create Item",
        "operationId": "createItem",
        "tags": ["tag1", "tag2"],
        "responses": {"201": {"description": "Created"}}
      }
    },
    "/users": {
      "get": {
        "summary": "List Users",
        "operationId": "listUsers",
        "tags": ["tag2"],
        "responses": {"200": {"description": "OK"}}
      }
    },
    "/ping": {
      "get": {
        "summary": "Simple ping",
        "operationId": "getPing",
        "responses": {"200": {"description": "OK"}}
      }
    }
  }
}`

// V2 Spec with tags and multiple operations
const complexV2SpecJSON = `{
  "swagger": "2.0",
  "info": {
    "title": "Complex V2 API",
    "version": "1.1.0"
  },
  "tags": [
    {"name": "tag1", "description": "First Tag"},
    {"name": "tag2", "description": "Second Tag"}
  ],
  "paths": {
    "/items": {
      "get": {
        "summary": "List Items",
        "operationId": "listItems",
        "tags": ["tag1"],
        "produces": ["application/json"],
        "responses": {"200": {"description": "OK"}}
      },
      "post": {
        "summary": "Create Item",
        "operationId": "createItem",
        "tags": ["tag1", "tag2"],
        "produces": ["application/json"],
        "responses": {"201": {"description": "Created"}}
      }
    },
    "/users": {
      "get": {
        "summary": "List Users",
        "operationId": "listUsers",
        "tags": ["tag2"],
        "produces": ["application/json"],
        "responses": {"200": {"description": "OK"}}
      }
    },
    "/ping": {
      "get": {
        "summary": "Simple ping",
        "operationId": "getPing",
        "produces": ["application/json"],
        "responses": {"200": {"description": "OK"}}
      }
    }
  }
}`

// V3 Spec with various parameter types and request body
const paramsV3SpecJSON = `{
  "openapi": "3.0.0",
  "info": {
    "title": "Params V3 API",
    "version": "1.0.0"
  },
  "paths": {
    "/test/{path_param}": {
      "post": {
        "summary": "Test various params",
        "operationId": "testParams",
        "parameters": [
          {
            "name": "path_param",
            "in": "path",
            "required": true,
            "schema": {"type": "integer", "format": "int32"}
          },
          {
            "name": "query_param",
            "in": "query",
            "required": true,
            "schema": {"type": "string", "enum": ["A", "B"]}
          },
          {
            "name": "optional_query",
            "in": "query",
            "schema": {"type": "boolean"}
          },
          {
            "name": "X-Header-Param",
            "in": "header",
            "required": true,
            "schema": {"type": "string"}
          },
          {
            "name": "CookieParam",
            "in": "cookie",
            "schema": {"type": "number"}
          }
        ],
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {
                "type": "object",
                "properties": {
                  "id": {"type": "string"},
                  "value": {"type": "number"}
                },
                "required": ["id"]
              }
            }
          }
        },
        "responses": {
          "200": {"description": "OK"}
        }
      }
    }
  }
}`

// V2 Spec with various parameter types and $ref
const paramsV2SpecJSON = `{
  "swagger": "2.0",
  "info": {
    "title": "Params V2 API",
    "version": "1.0.0"
  },
  "definitions": {
    "Item": {
      "type": "object",
      "properties": {
        "id": {"type": "string", "format": "uuid"},
        "name": {"type": "string"}
      },
      "required": ["id"]
    }
  },
  "paths": {
    "/test/{path_id}": {
      "put": {
        "summary": "Test V2 params and ref",
        "operationId": "testV2Params",
        "consumes": ["application/json"],
        "produces": ["application/json"],
        "parameters": [
          {
            "name": "path_id",
            "in": "path",
            "required": true,
            "type": "string"
          },
          {
            "name": "query_flag",
            "in": "query",
            "type": "boolean",
            "required": true
          },
          {
            "name": "X-Request-ID",
            "in": "header",
            "type": "string",
            "required": false
          },
          {
            "name": "body_param",
            "in": "body",
            "required": true,
            "schema": {
              "$ref": "#/definitions/Item"
            }
          }
        ],
        "responses": {
          "200": {"description": "OK"}
        }
      }
    }
  }
}`

// V3 Spec with array types
const arraysV3SpecJSON = `{
  "openapi": "3.0.0",
  "info": {"title": "Arrays V3 API", "version": "1.0.0"},
  "paths": {
    "/process": {
      "post": {
        "summary": "Process arrays",
        "operationId": "processArrays",
        "parameters": [
          {
            "name": "string_array_query",
            "in": "query",
            "schema": {
              "type": "array",
              "items": {"type": "string"}
            }
          }
        ],
        "requestBody": {
          "content": {
            "application/json": {
              "schema": {
                "type": "object",
                "properties": {
                  "int_array_body": {
                    "type": "array",
                    "items": {"type": "integer", "format": "int64"}
                  }
                }
              }
            }
          }
        },
        "responses": {"200": {"description": "OK"}}
      }
    }
  }
}`

// V2 Spec with array types
const arraysV2SpecJSON = `{
  "swagger": "2.0",
  "info": {"title": "Arrays V2 API", "version": "1.0.0"},
  "paths": {
    "/process": {
      "get": {
        "summary": "Get arrays",
        "operationId": "getArrays",
        "parameters": [
          {
            "name": "string_array_query",
            "in": "query",
            "type": "array",
            "items": {"type": "string"},
            "collectionFormat": "csv"
          },
          {
             "name": "int_array_form",
             "in": "formData",
             "type": "array",
             "items": {"type": "integer", "format": "int32"}
          }
        ],
        "responses": {"200": {"description": "OK"}}
      }
    }
  }
}`

// V2 Spec with file parameter
const fileV2SpecJSON = `{
  "swagger": "2.0",
  "info": {"title": "File V2 API", "version": "1.0.0"},
  "paths": {
    "/upload": {
      "post": {
        "summary": "Upload file",
        "operationId": "uploadFile",
        "consumes": ["multipart/form-data"],
        "parameters": [
          {
            "name": "description",
            "in": "formData",
            "type": "string"
          },
          {
            "name": "file_upload",
            "in": "formData",
            "required": true,
            "type": "file"
          }
        ],
        "responses": {"200": {"description": "OK"}}
      }
    }
  }
}`

// V3 spec with response schema
const responseSchemaV3SpecJSON = `{
  "openapi": "3.0.0",
  "info": {"title": "Response V3 API", "version": "1.0"},
  "paths": {
    "/file/{id}": {
      "get": {
        "operationId": "getFile",
        "parameters": [
          {"name": "id", "in": "path", "required": true, "schema": {"type": "string"}}
        ],
        "responses": {
          "200": {
            "description": "OK",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {"path": {"type": "string"}},
                  "required": ["path"]
                }
              }
            }
          }
        }
      }
    }
  }
}`

const responseSchemaV2SpecJSON = `{
  "swagger": "2.0",
  "info": {"title": "Response V2 API", "version": "1.0"},
  "paths": {
    "/file/{id}": {
      "get": {
        "operationId": "getFileV2",
        "produces": ["application/json"],
        "parameters": [
          {"name": "id", "in": "path", "required": true, "type": "string"}
        ],
        "responses": {
          "200": {
            "description": "OK",
            "schema": {
              "type": "object",
              "properties": {"path": {"type": "string"}},
              "required": ["path"]
            }
          }
        }
      }
    }
  }
}`

// V3 spec with response schema using $ref
const refResponseV3SpecJSON = `{
  "openapi": "3.0.0",
  "info": {"title": "Ref Response V3 API", "version": "1.0"},
  "components": {
    "schemas": {
      "Item": {
        "type": "object",
        "properties": {
          "id": {"type": "string"},
          "name": {"type": "string"}
        },
        "required": ["id"]
      }
    }
  },
  "paths": {
    "/item": {
      "get": {
        "operationId": "getItem",
        "responses": {
          "200": {
            "description": "OK",
            "content": {
              "application/json": {
                "schema": {"$ref": "#/components/schemas/Item"}
              }
            }
          }
        }
      }
    }
  }
}`

func TestLoadSwagger(t *testing.T) {
	tests := []struct {
		name          string
		content       string
		fileName      string
		expectError   bool
		expectVersion string
		containsError string           // Substring to check in error message
		isURLTest     bool             // Flag to indicate if the test uses a URL
		handler       http.HandlerFunc // Handler for mock HTTP server
	}{
		{
			name:          "Valid V3 JSON file",
			content:       minimalV3SpecJSON,
			fileName:      "valid_v3.json",
			expectError:   false,
			expectVersion: VersionV3,
		},
		{
			name:          "Valid V2 JSON file",
			content:       minimalV2SpecJSON,
			fileName:      "valid_v2.json",
			expectError:   false,
			expectVersion: VersionV2,
		},
		{
			name:          "Malformed JSON file",
			content:       malformedJSON,
			fileName:      "malformed.json",
			expectError:   true,
			containsError: "failed to parse JSON",
		},
		{
			name:          "No version key JSON file",
			content:       noVersionKeyJSON,
			fileName:      "no_version.json",
			expectError:   true,
			containsError: "missing 'openapi' or 'swagger' key",
		},
		{
			name:          "Non-existent file",
			content:       "", // No content needed
			fileName:      "non_existent.json",
			expectError:   true,
			containsError: "failed reading file path",
		},
		// --- URL Tests ---
		{
			name:          "Valid V3 JSON URL",
			content:       minimalV3SpecJSON,
			expectError:   false,
			expectVersion: VersionV3,
			isURLTest:     true,
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(minimalV3SpecJSON))
			},
		},
		{
			name:          "Valid V2 JSON URL",
			content:       minimalV2SpecJSON, // Content used by handler
			expectError:   false,
			expectVersion: VersionV2,
			isURLTest:     true,
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(minimalV2SpecJSON))
			},
		},
		{
			name:          "Malformed JSON URL",
			content:       malformedJSON,
			expectError:   true,
			containsError: "failed to parse JSON",
			isURLTest:     true,
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(malformedJSON))
			},
		},
		{
			name:          "No version key JSON URL",
			content:       noVersionKeyJSON,
			expectError:   true,
			containsError: "missing 'openapi' or 'swagger' key",
			isURLTest:     true,
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(noVersionKeyJSON))
			},
		},
		{
			name:          "URL Not Found (404)",
			expectError:   true,
			containsError: "failed to fetch URL", // Check for fetch error
			isURLTest:     true,
			handler: func(w http.ResponseWriter, r *http.Request) {
				http.NotFound(w, r) // Use standard http.NotFound
			},
		},
		{
			name:          "URL Internal Server Error (500)",
			expectError:   true,
			containsError: "failed to fetch URL", // Check for fetch error
			isURLTest:     true,
			handler: func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, "Internal Server Error", http.StatusInternalServerError) // Use standard http.Error
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var location string
			var server *httptest.Server // Declare server variable

			if tc.isURLTest {
				// Set up mock HTTP server
				require.NotNil(t, tc.handler, "URL test case must provide a handler")
				server = httptest.NewServer(tc.handler)
				defer server.Close()
				location = server.URL // Use the mock server's URL
			} else {
				// Existing file path logic
				tempDir := t.TempDir()
				filePath := filepath.Join(tempDir, tc.fileName)

				// Create the file only if content is provided
				if tc.content != "" {
					err := os.WriteFile(filePath, []byte(tc.content), 0644)
					require.NoError(t, err, "Failed to write temp spec file")
				}

				// For the non-existent file case, ensure it really doesn't exist
				if tc.name == "Non-existent file" {
					filePath = filepath.Join(tempDir, "definitely_not_here.json")
				}
				location = filePath
			}

			specDoc, version, err := LoadSwagger(location)

			if tc.expectError {
				assert.Error(t, err)
				if tc.containsError != "" {
					assert.True(t, strings.Contains(err.Error(), tc.containsError),
						"Error message %q does not contain expected substring %q", err.Error(), tc.containsError)
				}
				assert.Nil(t, specDoc)
				assert.Empty(t, version)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, specDoc)
				assert.Equal(t, tc.expectVersion, version)
				// Basic type assertion based on expected version
				if version == VersionV3 {
					assert.IsType(t, &openapi3.T{}, specDoc) // Expecting a pointer
				} else if version == VersionV2 {
					assert.IsType(t, &spec.Swagger{}, specDoc) // Expecting a pointer
				}
			}
		})
	}
}

// TODO: Add tests for GenerateToolSet
func TestGenerateToolSet(t *testing.T) {
	// --- Load Specs Once ---
	// Load V3 spec (error checked in TestLoadSwagger)
	tempDirV3 := t.TempDir()
	filePathV3 := filepath.Join(tempDirV3, "minimal_v3.json")
	err := os.WriteFile(filePathV3, []byte(minimalV3SpecJSON), 0644)
	require.NoError(t, err)
	docV3, versionV3, err := LoadSwagger(filePathV3)
	require.NoError(t, err)
	require.Equal(t, VersionV3, versionV3)
	specV3 := docV3.(*openapi3.T)

	// Load V2 spec (error checked in TestLoadSwagger)
	tempDirV2 := t.TempDir()
	filePathV2 := filepath.Join(tempDirV2, "minimal_v2.json")
	err = os.WriteFile(filePathV2, []byte(minimalV2SpecJSON), 0644)
	require.NoError(t, err)
	docV2, versionV2, err := LoadSwagger(filePathV2)
	require.NoError(t, err)
	require.Equal(t, VersionV2, versionV2)
	specV2 := docV2.(*spec.Swagger)

	// Load Complex V3 spec
	tempDirComplexV3 := t.TempDir()
	filePathComplexV3 := filepath.Join(tempDirComplexV3, "complex_v3.json")
	err = os.WriteFile(filePathComplexV3, []byte(complexV3SpecJSON), 0644)
	require.NoError(t, err)
	docComplexV3, versionComplexV3, err := LoadSwagger(filePathComplexV3)
	require.NoError(t, err)
	require.Equal(t, VersionV3, versionComplexV3)
	specComplexV3 := docComplexV3.(*openapi3.T)

	// Load Complex V2 spec
	tempDirComplexV2 := t.TempDir()
	filePathComplexV2 := filepath.Join(tempDirComplexV2, "complex_v2.json")
	err = os.WriteFile(filePathComplexV2, []byte(complexV2SpecJSON), 0644)
	require.NoError(t, err)
	docComplexV2, versionComplexV2, err := LoadSwagger(filePathComplexV2)
	require.NoError(t, err)
	require.Equal(t, VersionV2, versionComplexV2)
	specComplexV2 := docComplexV2.(*spec.Swagger)

	// Load Params V3 spec
	tempDirParamsV3 := t.TempDir()
	filePathParamsV3 := filepath.Join(tempDirParamsV3, "params_v3.json")
	err = os.WriteFile(filePathParamsV3, []byte(paramsV3SpecJSON), 0644)
	require.NoError(t, err)
	docParamsV3, versionParamsV3, err := LoadSwagger(filePathParamsV3)
	require.NoError(t, err)
	require.Equal(t, VersionV3, versionParamsV3)
	specParamsV3 := docParamsV3.(*openapi3.T)

	// Load Params V2 spec
	tempDirParamsV2 := t.TempDir()
	filePathParamsV2 := filepath.Join(tempDirParamsV2, "params_v2.json")
	err = os.WriteFile(filePathParamsV2, []byte(paramsV2SpecJSON), 0644)
	require.NoError(t, err)
	docParamsV2, versionParamsV2, err := LoadSwagger(filePathParamsV2)
	require.NoError(t, err)
	require.Equal(t, VersionV2, versionParamsV2)
	specParamsV2 := docParamsV2.(*spec.Swagger)

	// Load Arrays V3 spec
	tempDirArraysV3 := t.TempDir()
	filePathArraysV3 := filepath.Join(tempDirArraysV3, "arrays_v3.json")
	err = os.WriteFile(filePathArraysV3, []byte(arraysV3SpecJSON), 0644)
	require.NoError(t, err)
	docArraysV3, versionArraysV3, err := LoadSwagger(filePathArraysV3)
	require.NoError(t, err)
	require.Equal(t, VersionV3, versionArraysV3)
	specArraysV3 := docArraysV3.(*openapi3.T)

	// Load Arrays V2 spec
	tempDirArraysV2 := t.TempDir()
	filePathArraysV2 := filepath.Join(tempDirArraysV2, "arrays_v2.json")
	err = os.WriteFile(filePathArraysV2, []byte(arraysV2SpecJSON), 0644)
	require.NoError(t, err)
	docArraysV2, versionArraysV2, err := LoadSwagger(filePathArraysV2)
	require.NoError(t, err)
	require.Equal(t, VersionV2, versionArraysV2)
	specArraysV2 := docArraysV2.(*spec.Swagger)

	// Load File V2 spec
	tempDirFileV2 := t.TempDir()
	filePathFileV2 := filepath.Join(tempDirFileV2, "file_v2.json")
	err = os.WriteFile(filePathFileV2, []byte(fileV2SpecJSON), 0644)
	require.NoError(t, err)
	docFileV2, versionFileV2, err := LoadSwagger(filePathFileV2)
	require.NoError(t, err)
	require.Equal(t, VersionV2, versionFileV2)
	specFileV2 := docFileV2.(*spec.Swagger)

	// Load Response Schema V3 spec
	tempDirRespV3 := t.TempDir()
	filePathRespV3 := filepath.Join(tempDirRespV3, "resp_v3.json")
	err = os.WriteFile(filePathRespV3, []byte(responseSchemaV3SpecJSON), 0644)
	require.NoError(t, err)
	docRespV3, versionRespV3, err := LoadSwagger(filePathRespV3)
	require.NoError(t, err)
	require.Equal(t, VersionV3, versionRespV3)
	specRespV3 := docRespV3.(*openapi3.T)

	// Load Ref Response V3 spec
	tempDirRefRespV3 := t.TempDir()
	filePathRefRespV3 := filepath.Join(tempDirRefRespV3, "ref_resp_v3.json")
	err = os.WriteFile(filePathRefRespV3, []byte(refResponseV3SpecJSON), 0644)
	require.NoError(t, err)
	docRefRespV3, versionRefRespV3, err := LoadSwagger(filePathRefRespV3)
	require.NoError(t, err)
	require.Equal(t, VersionV3, versionRefRespV3)
	specRefRespV3 := docRefRespV3.(*openapi3.T)

	// Load Response Schema V2 spec
	tempDirRespV2 := t.TempDir()
	filePathRespV2 := filepath.Join(tempDirRespV2, "resp_v2.json")
	err = os.WriteFile(filePathRespV2, []byte(responseSchemaV2SpecJSON), 0644)
	require.NoError(t, err)
	docRespV2, versionRespV2, err := LoadSwagger(filePathRespV2)
	require.NoError(t, err)
	require.Equal(t, VersionV2, versionRespV2)
	specRespV2 := docRespV2.(*spec.Swagger)

	// --- Test Cases ---
	tests := []struct {
		name            string
		spec            interface{}
		version         string
		cfg             *config.Config
		expectError     bool
		expectedToolSet *mcp.ToolSet // Define expected basic structure
	}{
		{
			name:        "V3 Minimal Spec - Default Config",
			spec:        specV3,
			version:     VersionV3,
			cfg:         &config.Config{}, // Default empty config
			expectError: false,
			expectedToolSet: &mcp.ToolSet{
				Name:        "Minimal V3 API",
				Description: "",
				Tools: []mcp.Tool{
					{
						Name:        "getPing",
						Description: "Simple ping endpoint",
						InputSchema: mcp.Schema{Type: "object", Properties: map[string]mcp.Schema{}, Required: []string{}},
					},
				},
				Operations: map[string]mcp.OperationDetail{
					"getPing": {
						Method:     "GET",
						Path:       "/ping",
						BaseURL:    "",                      // No server defined
						Parameters: []mcp.ParameterDetail{}, // Expect empty slice
					},
				},
			},
		},
		{
			name:        "V2 Minimal Spec - Default Config",
			spec:        specV2,
			version:     VersionV2,
			cfg:         &config.Config{}, // Default empty config
			expectError: false,
			expectedToolSet: &mcp.ToolSet{
				Name:        "Minimal V2 API",
				Description: "",
				Tools: []mcp.Tool{
					{
						Name:        "getHealth",
						Description: "Simple health check",
						InputSchema: mcp.Schema{Type: "object", Properties: map[string]mcp.Schema{}, Required: []string{}},
					},
				},
				Operations: map[string]mcp.OperationDetail{
					"getHealth": {
						Method:     "GET",
						Path:       "/health",
						BaseURL:    "",                      // No host/schemes/basePath
						Parameters: []mcp.ParameterDetail{}, // Expect empty slice
					},
				},
			},
		},
		{
			name:    "V3 Minimal Spec - Config Overrides",
			spec:    specV3,
			version: VersionV3,
			cfg: &config.Config{
				ServerBaseURL:   "http://override.com/v1",
				DefaultToolName: "Override Name",
				DefaultToolDesc: "Override Desc",
			},
			expectError: false,
			expectedToolSet: &mcp.ToolSet{
				Name:        "Override Name", // Uses override
				Description: "Override Desc", // Uses override
				Tools: []mcp.Tool{
					{
						Name:        "getPing",
						Description: "Simple ping endpoint",
						InputSchema: mcp.Schema{Type: "object", Properties: map[string]mcp.Schema{}, Required: []string{}},
					},
				},
				Operations: map[string]mcp.OperationDetail{
					"getPing": {
						Method:     "GET",
						Path:       "/ping",
						BaseURL:    "http://override.com/v1", // Uses override
						Parameters: []mcp.ParameterDetail{},  // Expect empty slice
					},
				},
			},
		},
		// --- Filtering Tests (Using Complex Specs) ---
		{
			name:        "V3 Complex - Include Tag1",
			spec:        specComplexV3,
			version:     VersionV3,
			cfg:         &config.Config{IncludeTags: []string{"tag1"}},
			expectError: false,
			expectedToolSet: &mcp.ToolSet{
				Name: "Complex V3 API", Description: "", // Should only include listItems and createItem
				Tools:      []mcp.Tool{{Name: "listItems"}, {Name: "createItem"}},             // Simplified for length check
				Operations: map[string]mcp.OperationDetail{"listItems": {}, "createItem": {}}, // Simplified for length check
			},
		},
		{
			name:        "V3 Complex - Exclude Tag2",
			spec:        specComplexV3,
			version:     VersionV3,
			cfg:         &config.Config{ExcludeTags: []string{"tag2"}},
			expectError: false,
			expectedToolSet: &mcp.ToolSet{
				Name: "Complex V3 API", Description: "", // Should include listItems and getPing
				Tools:      []mcp.Tool{{Name: "listItems"}, {Name: "getPing"}},             // Simplified for length check
				Operations: map[string]mcp.OperationDetail{"listItems": {}, "getPing": {}}, // Simplified for length check
			},
		},
		{
			name:        "V3 Complex - Include Operation listItems",
			spec:        specComplexV3,
			version:     VersionV3,
			cfg:         &config.Config{IncludeOperations: []string{"listItems"}},
			expectError: false,
			expectedToolSet: &mcp.ToolSet{
				Name: "Complex V3 API", Description: "", // Should include only listItems
				Tools:      []mcp.Tool{{Name: "listItems"}},                 // Simplified for length check
				Operations: map[string]mcp.OperationDetail{"listItems": {}}, // Simplified for length check
			},
		},
		{
			name:        "V3 Complex - Exclude Operation createItem, getPing",
			spec:        specComplexV3,
			version:     VersionV3,
			cfg:         &config.Config{ExcludeOperations: []string{"createItem", "getPing"}},
			expectError: false,
			expectedToolSet: &mcp.ToolSet{
				Name: "Complex V3 API", Description: "", // Should include listItems and listUsers
				Tools:      []mcp.Tool{{Name: "listItems"}, {Name: "listUsers"}},             // Simplified for length check
				Operations: map[string]mcp.OperationDetail{"listItems": {}, "listUsers": {}}, // Simplified for length check
			},
		},
		{
			name:        "V2 Complex - Include Tag1",
			spec:        specComplexV2,
			version:     VersionV2,
			cfg:         &config.Config{IncludeTags: []string{"tag1"}},
			expectError: false,
			expectedToolSet: &mcp.ToolSet{
				Name: "Complex V2 API", Description: "", // Should only include listItems and createItem
				Tools:      []mcp.Tool{{Name: "listItems"}, {Name: "createItem"}},             // Simplified for length check
				Operations: map[string]mcp.OperationDetail{"listItems": {}, "createItem": {}}, // Simplified for length check
			},
		},
		{
			name:        "V2 Complex - Exclude Tag2",
			spec:        specComplexV2,
			version:     VersionV2,
			cfg:         &config.Config{ExcludeTags: []string{"tag2"}},
			expectError: false,
			expectedToolSet: &mcp.ToolSet{
				Name: "Complex V2 API", Description: "", // Should include listItems and getPing
				Tools:      []mcp.Tool{{Name: "listItems"}, {Name: "getPing"}},             // Simplified for length check
				Operations: map[string]mcp.OperationDetail{"listItems": {}, "getPing": {}}, // Simplified for length check
			},
		},
		// --- Parameter/Schema Tests ---
		{
			name:        "V3 Params and Request Body",
			spec:        specParamsV3,
			version:     VersionV3,
			cfg:         &config.Config{},
			expectError: false,
			expectedToolSet: &mcp.ToolSet{
				Name:        "Params V3 API",
				Description: "", // Updated: No description in spec info
				Tools: []mcp.Tool{
					{
						Name:        "testParams",
						Description: "Test various params",
						InputSchema: mcp.Schema{
							Type: "object",
							Properties: map[string]mcp.Schema{
								// Parameters merged with Request Body properties
								"path_param":     {Type: "integer", Format: "int32"},
								"query_param":    {Type: "string", Enum: []interface{}{"A", "B"}},
								"optional_query": {Type: "boolean"},
								"X-Header-Param": {Type: "string"},
								"CookieParam":    {Type: "number"},
								"id":             {Type: "string"},
								"value":          {Type: "number"},
							},
							Required: []string{"path_param", "query_param", "X-Header-Param", "id"}, // Order might differ, will sort before assert
						},
					},
				},
				Operations: map[string]mcp.OperationDetail{
					"testParams": {
						Method:  "POST",
						Path:    "/test/{path_param}",
						BaseURL: "", // No server
						Parameters: []mcp.ParameterDetail{
							{Name: "path_param", In: "path"},
							{Name: "query_param", In: "query"},
							{Name: "optional_query", In: "query"},
							{Name: "X-Header-Param", In: "header"},
							{Name: "CookieParam", In: "cookie"},
						},
					},
				},
			},
		},
		{
			name:        "V2 Params and Ref",
			spec:        specParamsV2,
			version:     VersionV2,
			cfg:         &config.Config{},
			expectError: false,
			expectedToolSet: &mcp.ToolSet{
				Name:        "Params V2 API",
				Description: "", // Corrected: No description in spec info
				Tools: []mcp.Tool{
					{
						Name:        "testV2Params",
						Description: "Test V2 params and ref",
						InputSchema: mcp.Schema{
							Type: "object",
							Properties: map[string]mcp.Schema{
								// Path, Query, Header params first
								"path_id":      {Type: "string"},
								"query_flag":   {Type: "boolean"},
								"X-Request-ID": {Type: "string"},
								// Body param ($ref to Item) merged
								"id":   {Type: "string", Format: "uuid"},
								"name": {Type: "string"},
							},
							Required: []string{"path_id", "query_flag", "id"}, // Required params + required definition props
						},
					},
				},
				Operations: map[string]mcp.OperationDetail{
					"testV2Params": {
						Method:  "PUT",
						Path:    "/test/{path_id}",
						BaseURL: "", // No server
						Parameters: []mcp.ParameterDetail{
							{Name: "path_id", In: "path"},
							{Name: "query_flag", In: "query"},
							{Name: "X-Request-ID", In: "header"},
							{Name: "body_param", In: "body"}, // Body param listed here
						},
					},
				},
			},
		},
		// --- Array Tests ---
		{
			name:        "V3 Arrays",
			spec:        specArraysV3,
			version:     VersionV3,
			cfg:         &config.Config{},
			expectError: false,
			expectedToolSet: &mcp.ToolSet{
				Name: "Arrays V3 API", Description: "",
				Tools: []mcp.Tool{
					{
						Name:        "processArrays",
						Description: "Process arrays",
						InputSchema: mcp.Schema{
							Type: "object",
							Properties: map[string]mcp.Schema{
								"string_array_query": {Type: "array", Items: &mcp.Schema{Type: "string"}},
								"int_array_body":     {Type: "array", Items: &mcp.Schema{Type: "integer", Format: "int64"}},
							},
							Required: []string{}, // No required fields specified
						},
					},
				},
				Operations: map[string]mcp.OperationDetail{
					"processArrays": {
						Method:  "POST",
						Path:    "/process",
						BaseURL: "",
						Parameters: []mcp.ParameterDetail{
							{Name: "string_array_query", In: "query"},
							// Body param details are not explicitly listed in V3 op details
						},
					},
				},
			},
		},
		{
			name:        "V2 Arrays",
			spec:        specArraysV2,
			version:     VersionV2,
			cfg:         &config.Config{},
			expectError: false,
			expectedToolSet: &mcp.ToolSet{
				Name: "Arrays V2 API", Description: "",
				Tools: []mcp.Tool{
					{
						Name:        "getArrays",
						Description: "Get arrays",
						InputSchema: mcp.Schema{
							Type: "object",
							Properties: map[string]mcp.Schema{
								"string_array_query": {Type: "array", Items: &mcp.Schema{Type: "string"}},
								"int_array_form":     {Type: "array", Items: &mcp.Schema{Type: "integer", Format: "int32"}},
							},
							Required: []string{}, // No required fields specified
						},
					},
				},
				Operations: map[string]mcp.OperationDetail{
					"getArrays": {
						Method:  "GET",
						Path:    "/process",
						BaseURL: "",
						Parameters: []mcp.ParameterDetail{
							{Name: "string_array_query", In: "query"},
							{Name: "int_array_form", In: "formData"},
						},
					},
				},
			},
		},
		{
			name:        "V2 File Param",
			spec:        specFileV2,
			version:     VersionV2,
			cfg:         &config.Config{},
			expectError: false,
			expectedToolSet: &mcp.ToolSet{
				Name: "File V2 API", Description: "",
				Tools: []mcp.Tool{
					{
						Name:        "uploadFile",
						Description: "Upload file",
						InputSchema: mcp.Schema{
							Type: "object",
							Properties: map[string]mcp.Schema{
								"description": {Type: "string"},
								"file_upload": {Type: "string"}, // file type maps to string
							},
							Required: []string{"file_upload"}, // file_upload is required
						},
					},
				},
				Operations: map[string]mcp.OperationDetail{
					"uploadFile": {
						Method:  "POST",
						Path:    "/upload",
						BaseURL: "",
						Parameters: []mcp.ParameterDetail{
							{Name: "description", In: "formData"},
							{Name: "file_upload", In: "formData"},
						},
					},
				},
			},
		},
		{
			name:        "V3 Response Schema",
			spec:        specRespV3,
			version:     VersionV3,
			cfg:         &config.Config{},
			expectError: false,
			expectedToolSet: &mcp.ToolSet{
				Name: "Response V3 API", Description: "",
				Tools: []mcp.Tool{
					{
						Name:         "getFile",
						InputSchema:  mcp.Schema{Type: "object", Properties: map[string]mcp.Schema{"id": {Type: "string"}}, Required: []string{"id"}},
						OutputSchema: mcp.Schema{Type: "object", Properties: map[string]mcp.Schema{"path": {Type: "string"}}, Required: []string{"path"}},
					},
				},
				Operations: map[string]mcp.OperationDetail{
					"getFile": {Method: "GET", Path: "/file/{id}", BaseURL: "", Parameters: []mcp.ParameterDetail{{Name: "id", In: "path"}}},
				},
			},
		},
		{
			name:        "V3 Response Schema Ref",
			spec:        specRefRespV3,
			version:     VersionV3,
			cfg:         &config.Config{},
			expectError: false,
			expectedToolSet: &mcp.ToolSet{
				Name: "Ref Response V3 API", Description: "",
				Tools: []mcp.Tool{
					{
						Name:         "getItem",
						InputSchema:  mcp.Schema{Type: "object", Properties: map[string]mcp.Schema{}, Required: []string{}},
						OutputSchema: mcp.Schema{Type: "object", Properties: map[string]mcp.Schema{"id": {Type: "string"}, "name": {Type: "string"}}, Required: []string{"id"}},
					},
				},
				Operations: map[string]mcp.OperationDetail{
					"getItem": {Method: "GET", Path: "/item", BaseURL: "", Parameters: []mcp.ParameterDetail{}},
				},
			},
		},
		{
			name:        "V2 Response Schema",
			spec:        specRespV2,
			version:     VersionV2,
			cfg:         &config.Config{},
			expectError: false,
			expectedToolSet: &mcp.ToolSet{
				Name: "Response V2 API", Description: "",
				Tools: []mcp.Tool{
					{
						Name:         "getFileV2",
						InputSchema:  mcp.Schema{Type: "object", Properties: map[string]mcp.Schema{"id": {Type: "string"}}, Required: []string{"id"}},
						OutputSchema: mcp.Schema{Type: "object", Properties: map[string]mcp.Schema{"path": {Type: "string"}}, Required: []string{"path"}},
					},
				},
				Operations: map[string]mcp.OperationDetail{
					"getFileV2": {Method: "GET", Path: "/file/{id}", BaseURL: "", Parameters: []mcp.ParameterDetail{{Name: "id", In: "path"}}},
				},
			},
		},
		// TODO: Add V3/V2 tests for refs
		// TODO: Add V3/V2 tests for file types (V2)
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			toolSet, err := GenerateToolSet(tc.spec, tc.version, tc.cfg)

			if tc.expectError {
				assert.Error(t, err)
				assert.Nil(t, toolSet)
			} else {
				assert.NoError(t, err)
				require.NotNil(t, toolSet)

				// Compare basic ToolSet fields
				assert.Equal(t, tc.expectedToolSet.Name, toolSet.Name, "ToolSet Name mismatch")
				assert.Equal(t, tc.expectedToolSet.Description, toolSet.Description, "ToolSet Description mismatch")

				// Compare Tool/Operation counts first for filtering tests
				assert.Equal(t, len(tc.expectedToolSet.Tools), len(toolSet.Tools), "Tool count mismatch")
				assert.Equal(t, len(tc.expectedToolSet.Operations), len(toolSet.Operations), "Operation count mismatch")

				// If counts match, check specific tool names exist (more robust for filtering tests)
				if len(tc.expectedToolSet.Tools) == len(toolSet.Tools) {
					actualToolNames := make(map[string]bool)
					for _, actualTool := range toolSet.Tools {
						actualToolNames[actualTool.Name] = true
					}
					for _, expectedTool := range tc.expectedToolSet.Tools {
						assert.Contains(t, actualToolNames, expectedTool.Name, "Expected tool %s not found in actual tools", expectedTool.Name)
					}
				}

				// If counts match, check specific operation IDs exist (more robust for filtering tests)
				if len(tc.expectedToolSet.Operations) == len(toolSet.Operations) {
					for opID := range tc.expectedToolSet.Operations {
						assert.Contains(t, toolSet.Operations, opID, "Expected operation detail %s not found", opID)
					}
				}

				// Full comparison only for non-filtering tests for now (can be expanded)
				if !strings.Contains(tc.name, "Complex") {
					// Compare Tools slice fully
					for i, expectedTool := range tc.expectedToolSet.Tools {
						if i < len(toolSet.Tools) { // Bounds check
							actualTool := toolSet.Tools[i]
							assert.Equal(t, expectedTool.Name, actualTool.Name, "Tool[%d] Name mismatch", i)
							assert.Equal(t, expectedTool.Description, actualTool.Description, "Tool[%d] Description mismatch", i)
							// Sort Required slices before comparing Schemas
							expectedSchema := expectedTool.InputSchema
							actualSchema := actualTool.InputSchema
							sort.Strings(expectedSchema.Required)
							sort.Strings(actualSchema.Required)
							assert.Equal(t, expectedSchema, actualSchema, "Tool[%d] InputSchema mismatch", i)
						}
					}
					// Compare Operations map fully
					for opID, expectedOpDetail := range tc.expectedToolSet.Operations {
						if actualOpDetail, ok := toolSet.Operations[opID]; ok {
							assert.Equal(t, expectedOpDetail.Method, actualOpDetail.Method, "OpDetail %s Method mismatch", opID)
							assert.Equal(t, expectedOpDetail.Path, actualOpDetail.Path, "OpDetail %s Path mismatch", opID)
							assert.Equal(t, expectedOpDetail.BaseURL, actualOpDetail.BaseURL, "OpDetail %s BaseURL mismatch", opID)
							assert.Equal(t, expectedOpDetail.Parameters, actualOpDetail.Parameters, "OpDetail %s Parameters mismatch", opID)
						}
					}
				}
			}
		})
	}
}
