package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"text/template"

	"github.com/BurntSushi/toml"
	"github.com/google/shlex" // Added for command parsing
	"gopkg.in/yaml.v3"
)

// stringSlice is a custom type for accepting multiple string flags
type stringSlice []string

func (s *stringSlice) String() string {
	return strings.Join(*s, ", ")
}

func (s *stringSlice) Set(value string) error {
	*s = append(*s, value)
	return nil
}

// fileMap stores file ID and its path
type fileMap map[string]string

// updateRule defines how to update a local config file
type updateRule struct {
	FileID     string
	Path       []string
	Template   *template.Template
	RawContent string // Store the raw template string
}

func main() {
	urlFlag := flag.String("url", "", "Remote config data JSON file URL")
	var fileFlags stringSlice
	flag.Var(&fileFlags, "file", "Local config file to update (id=path). Must exist. Can be used multiple times.")
	var updateFlags stringSlice
	flag.Var(&updateFlags, "update", "Rules to update local files (<file-id>.<key>=<content-template>). Can be used multiple times.")
	preCmdFlag := flag.String("pre", "", "Custom command to execute before updates (parsed with shlex).")
	postCmdFlag := flag.String("post", "", "Custom command to execute after updates (parsed with shlex).")

	flag.Parse()

	if *urlFlag == "" {
		log.Fatal("Error: 'url' flag is required")
	}
	if len(fileFlags) == 0 {
		log.Fatal("Error: at least one 'file' flag is required")
	}
	if len(updateFlags) == 0 {
		log.Fatal("Error: at least one 'update' flag is required")
	}

	// Execute Pre-command
	if *preCmdFlag != "" {
		log.Printf("Executing pre-update command: %s", *preCmdFlag)
		if err := executeCommand(*preCmdFlag); err != nil {
			log.Fatalf("Error executing pre-update command '%s': %v. Aborting.", *preCmdFlag, err)
		}
		log.Println("Pre-update command executed successfully.")
	}

	// 1. Fetch remote config data
	remoteConfig, err := fetchRemoteConfig(*urlFlag)
	if err != nil {
		log.Fatalf("Error fetching remote config from %s: %v", *urlFlag, err)
	}
	log.Printf("Successfully fetched remote config from %s", *urlFlag)

	// 2. Parse file flags
	localFiles := make(fileMap)
	for _, f := range fileFlags {
		parts := strings.SplitN(f, "=", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			log.Fatalf("Error: invalid 'file' flag format: %s. Expected 'id=path'", f)
		}
		localFiles[parts[0]] = parts[1]
		log.Printf("Registered local file: ID='%s', Path='%s'", parts[0], parts[1])
	}

	// 3. Parse update rules
	var rules []updateRule
	for _, u := range updateFlags {
		parts := strings.SplitN(u, "=", 2)
		if len(parts) != 2 || parts[0] == "" {
			log.Fatalf("Error: invalid 'update' flag format: %s. Expected '<file-id>.<key>=<content-template>'", u)
		}
		keyParts := strings.Split(parts[0], ".")
		if len(keyParts) < 2 {
			log.Fatalf("Error: invalid key in 'update' flag: %s. Expected '<file-id>.<key.subkey...>'", parts[0])
		}
		fileID := keyParts[0]
		if _, ok := localFiles[fileID]; !ok {
			log.Fatalf("Error: file ID '%s' in update rule '%s' not defined in 'file' flags", fileID, u)
		}

		tmpl, err := template.New(parts[0]).Parse(parts[1])
		if err != nil {
			log.Fatalf("Error parsing template for rule '%s': %v", u, err)
		}
		rules = append(rules, updateRule{
			FileID:     fileID,
			Path:       keyParts[1:],
			Template:   tmpl,
			RawContent: parts[1],
		})
		log.Printf("Registered update rule: FileID='%s', Path='%s', Template='%s'", fileID, strings.Join(keyParts[1:], "."), parts[1])
	}

	// 4. Process each local file
	for fileID, filePath := range localFiles {
		log.Printf("Processing file: ID='%s', Path='%s'", fileID, filePath)
		err := processFile(fileID, filePath, remoteConfig, rules)
		if err != nil {
			log.Printf("Error processing file %s: %v", filePath, err)
			// Continue to next file even if one fails
		}
	}

	// Execute Post-command
	if *postCmdFlag != "" {
		log.Printf("Executing post-update command: %s", *postCmdFlag)
		if err := executeCommand(*postCmdFlag); err != nil {
			log.Printf("Warning: Error executing post-update command '%s': %v", *postCmdFlag, err)
			// Do not abort for post-command failure, just log it.
		} else {
			log.Println("Post-update command executed successfully.")
		}
	}

	log.Println("remoteconf execution finished.")
}

func executeCommand(commandStr string) error {
	log.Printf("Shell-parsing command string: %s", commandStr)
	parts, err := shlex.Split(commandStr)
	if err != nil {
		return fmt.Errorf("failed to parse command string '%s': %w", commandStr, err)
	}

	if len(parts) == 0 {
		// This case should ideally be prevented by the check `if *CmdFlag != ""` in main,
		// but shlex.Split on an empty or whitespace-only string might also result in empty parts.
		log.Println("Parsed command string resulted in no executable command (empty or whitespace). Skipping execution.")
		return nil // Or return an error if an empty command string flag should be an error
	}

	commandName := parts[0]
	var args []string
	if len(parts) > 1 {
		args = parts[1:]
	}

	log.Printf("Running command: '%s' with arguments %v", commandName, args)
	cmd := exec.Command(commandName, args...)

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func fetchRemoteConfig(url string) (map[string]interface{}, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch URL: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch URL: status code %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var config map[string]interface{}
	err = json.Unmarshal(body, &config)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal remote JSON: %w", err)
	}
	return config, nil
}

func readFile(filePath string) (map[string]interface{}, []byte, string, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			// File must exist, this is an error condition handled by processFile
			return nil, nil, "", err
		}
		return nil, nil, "", fmt.Errorf("failed to read file %s: %w", filePath, err)
	}

	var data map[string]interface{}
	ext := strings.ToLower(filepath.Ext(filePath))

	switch ext {
	case ".json":
		decoder := json.NewDecoder(bytes.NewReader(content))
		decoder.UseNumber() // Important for preserving number types accurately
		err = decoder.Decode(&data)
		if err != nil {
			return nil, content, ext, fmt.Errorf("failed to unmarshal JSON from %s: %w", filePath, err)
		}
	case ".yaml", ".yml":
		err = yaml.Unmarshal(content, &data)
		if err != nil {
			return nil, content, ext, fmt.Errorf("failed to unmarshal YAML from %s: %w", filePath, err)
		}
		if data == nil { // Ensure data is a map even for empty YAML.
			data = make(map[string]interface{})
		}
	case ".toml":
		_, err = toml.Decode(string(content), &data) // toml.Unmarshal is an alias
		if err != nil {
			return nil, content, ext, fmt.Errorf("failed to unmarshal TOML from %s: %w", filePath, err)
		}
	default:
		return nil, content, ext, fmt.Errorf("unsupported file extension: %s for file %s", ext, filePath)
	}
	return data, content, ext, nil
}

func writeFile(filePath string, data map[string]interface{}, format string) error {
	var newContent []byte
	var err error

	switch format {
	case ".json":
		newContent, err = json.MarshalIndent(data, "", "  ")
	case ".yaml", ".yml":
		newContent, err = yaml.Marshal(data)
	case ".toml":
		var buf bytes.Buffer
		encoder := toml.NewEncoder(&buf)
		err = encoder.Encode(data)
		if err == nil {
			newContent = buf.Bytes()
		}
	default:
		return fmt.Errorf("unsupported file extension for writing: %s", format)
	}

	if err != nil {
		return fmt.Errorf("failed to marshal data for %s: %w", filePath, err)
	}

	err = os.WriteFile(filePath, newContent, 0644) // Assume file exists, so dir also exists
	if err != nil {
		return fmt.Errorf("failed to write file %s: %w", filePath, err)
	}
	return nil
}

func processFile(fileID string, filePath string, remoteConfig map[string]interface{}, allRules []updateRule) error {
	localData, originalRawContent, format, err := readFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("Error: Local config file %s (ID: %s) must exist but was not found. Skipping this file.", filePath, fileID)
			return nil // Not a fatal error for the whole program, but this file is skipped.
		}
		return fmt.Errorf("could not read initial state of %s: %w", filePath, err)
	}

	modifiedData := deepCopyMap(localData) // Work on a copy

	fileSpecificRules := []updateRule{}
	for _, rule := range allRules {
		if rule.FileID == fileID {
			fileSpecificRules = append(fileSpecificRules, rule)
		}
	}

	if len(fileSpecificRules) == 0 {
		log.Printf("No update rules found for file ID '%s'. Skipping modification.", fileID)
		return nil
	}

	changedOverall := false
	for _, rule := range fileSpecificRules {
		currentVal, originalType, found := getNestedValueAndType(modifiedData, rule.Path)
		if !found {
			log.Printf("Warning: Path '%s' not found in file %s (ID: %s). Cannot update as field must exist. Skipping this rule.", strings.Join(rule.Path, "."), filePath, fileID)
			continue
		}

		var tplOutput bytes.Buffer
		if err := rule.Template.Execute(&tplOutput, remoteConfig); err != nil {
			log.Printf("Warning: Failed to execute template for rule (FileID: %s, Path: %v): %v. Skipping this rule.", rule.FileID, rule.Path, err)
			continue
		}
		newValueStr := tplOutput.String()

		finalValue, err := convertToOriginalType(newValueStr, originalType, rule.Path)
		if err != nil {
			log.Printf("Warning: Type conversion failed for path '%s' in file %s (ID: %s): %v. Value from template: '%s'. Expected type similar to original. Skipping this rule.", strings.Join(rule.Path, "."), filePath, fileID, err, newValueStr)
			continue
		}

		if !reflect.DeepEqual(currentVal, finalValue) {
			setNestedValue(modifiedData, rule.Path, finalValue)
			log.Printf("  Applied update to %s: Path='%s', NewValue='%v' (Type: %T)", filePath, strings.Join(rule.Path, "."), finalValue, finalValue)
			changedOverall = true
		} else {
			log.Printf("  Skipped update (no change) for %s: Path='%s', Value='%v'", filePath, strings.Join(rule.Path, "."), finalValue)
		}
	}

	if !changedOverall {
		log.Printf("No effective changes detected for %s. File not modified.", filePath)
		return nil
	}

	var updatedRawContent []byte
	var marshalErr error
	switch format {
	case ".json":
		updatedRawContent, marshalErr = json.MarshalIndent(modifiedData, "", "  ")
	case ".yaml", ".yml":
		updatedRawContent, marshalErr = yaml.Marshal(modifiedData)
	case ".toml":
		var buf bytes.Buffer
		encoder := toml.NewEncoder(&buf)
		marshalErr = encoder.Encode(modifiedData)
		if marshalErr == nil {
			updatedRawContent = buf.Bytes()
		}
	default:
		return fmt.Errorf("internal error: unsupported format for final comparison %s", format)
	}

	if marshalErr != nil {
		return fmt.Errorf("failed to marshal modified data for comparison for %s: %w", filePath, marshalErr)
	}

	normOriginal := strings.TrimSpace(string(originalRawContent))
	normUpdated := strings.TrimSpace(string(updatedRawContent))

	if normOriginal == normUpdated {
		log.Printf("Content for %s is semantically the same after updates, although internal structure might have been marked changed. File not written to avoid format churn.", filePath)
		return nil
	}

	log.Printf("Changes detected for %s. Writing updated file.", filePath)
	return writeFile(filePath, modifiedData, format)
}

func convertToOriginalType(newValueStr string, originalType reflect.Type, path []string) (interface{}, error) {
	if strings.ToLower(newValueStr) == "null" {
		return nil, nil
	}

	if originalType == nil {
		if iVal, err := strconv.ParseInt(newValueStr, 10, 64); err == nil {
			return iVal, nil
		} else if fVal, err := strconv.ParseFloat(newValueStr, 64); err == nil {
			return fVal, nil
		} else if bVal, err := strconv.ParseBool(newValueStr); err == nil {
			return bVal, nil
		}
		if len(newValueStr) >= 2 && newValueStr[0] == '"' && newValueStr[len(newValueStr)-1] == '"' {
			if unquoted, err := strconv.Unquote(newValueStr); err == nil {
				return unquoted, nil
			}
		}
		return newValueStr, nil
	}

	switch originalType.Kind() {
	case reflect.String:
		return newValueStr, nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		iVal, err := strconv.ParseInt(newValueStr, 10, originalType.Bits())
		if err != nil {
			return nil, fmt.Errorf("cannot convert '%s' to %s for path %v: %w", newValueStr, originalType.Kind(), path, err)
		}
		val := reflect.New(originalType).Elem()
		val.SetInt(iVal)
		return val.Interface(), nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		uVal, err := strconv.ParseUint(newValueStr, 10, originalType.Bits())
		if err != nil {
			return nil, fmt.Errorf("cannot convert '%s' to %s for path %v: %w", newValueStr, originalType.Kind(), path, err)
		}
		val := reflect.New(originalType).Elem()
		val.SetUint(uVal)
		return val.Interface(), nil
	case reflect.Float32, reflect.Float64:
		fVal, err := strconv.ParseFloat(newValueStr, originalType.Bits())
		if err != nil {
			return nil, fmt.Errorf("cannot convert '%s' to %s for path %v: %w", newValueStr, originalType.Kind(), path, err)
		}
		val := reflect.New(originalType).Elem()
		val.SetFloat(fVal)
		return val.Interface(), nil
	case reflect.Bool:
		bVal, err := strconv.ParseBool(newValueStr)
		if err != nil {
			return nil, fmt.Errorf("cannot convert '%s' to bool for path %v: %w", newValueStr, path, err)
		}
		return bVal, nil
	case reflect.Interface:
		if num, ok := originalType.MethodByName("Float64"); ok && num.Type.NumIn() == 0 && num.Type.NumOut() == 2 {
			if fVal, err := strconv.ParseFloat(newValueStr, 64); err == nil {
				return fVal, nil
			}
		}
		if iVal, err := strconv.ParseInt(newValueStr, 10, 64); err == nil {
			return iVal, nil
		}
		if fVal, err := strconv.ParseFloat(newValueStr, 64); err == nil {
			return fVal, nil
		}
		if bVal, err := strconv.ParseBool(newValueStr); err == nil {
			return bVal, nil
		}
		return newValueStr, nil
	default:
		return nil, fmt.Errorf("unsupported type %s for automatic conversion at path %v. Value: '%s'", originalType.Kind(), path, newValueStr)
	}
}

func setNestedValue(data map[string]interface{}, path []string, value interface{}) {
	current := data
	for i, key := range path {
		if i == len(path)-1 {
			current[key] = value
			return
		}
		if nextMap, ok := current[key].(map[string]interface{}); ok {
			current = nextMap
		} else {
			log.Printf("Error: Path segment '%s' in '%s' is not a map, cannot set nested value.", key, strings.Join(path, "."))
			return
		}
	}
}

func getNestedValueAndType(data map[string]interface{}, path []string) (value interface{}, valType reflect.Type, found bool) {
	current := interface{}(data)
	for i, key := range path {
		currentMap, ok := current.(map[string]interface{})
		if !ok {
			return nil, nil, false
		}
		val, exists := currentMap[key]
		if !exists {
			return nil, nil, false
		}
		current = val
		if i == len(path)-1 {
			return current, reflect.TypeOf(current), true
		}
	}
	if len(path) == 0 {
		return data, reflect.TypeOf(data), true
	}
	return nil, nil, false
}

func deepCopyMap(original map[string]interface{}) map[string]interface{} {
	if original == nil {
		return nil
	}
	newMap := make(map[string]interface{})
	for key, value := range original {
		if subMap, ok := value.(map[string]interface{}); ok {
			newMap[key] = deepCopyMap(subMap)
		} else if subSlice, ok := value.([]interface{}); ok {
			newMap[key] = deepCopySlice(subSlice)
		} else {
			newMap[key] = value
		}
	}
	return newMap
}

func deepCopySlice(original []interface{}) []interface{} {
	if original == nil {
		return nil
	}
	newSlice := make([]interface{}, len(original))
	for i, value := range original {
		if subMap, ok := value.(map[string]interface{}); ok {
			newSlice[i] = deepCopyMap(subMap)
		} else if subSlice, ok := value.([]interface{}); ok {
			newSlice[i] = deepCopySlice(subSlice)
		} else {
			newSlice[i] = value
		}
	}
	return newSlice
}
