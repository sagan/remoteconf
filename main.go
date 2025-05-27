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
	"github.com/google/shlex"
	"gopkg.in/yaml.v3"
)

// VERSION defines the program version.
// Future changes should update this according to Semantic Versioning rules.
const VERSION = "v0.1.0"

// stringSlice is a custom type for accepting multiple string flags
type stringSlice []string

func (s *stringSlice) String() string {
	return strings.Join(*s, ", ")
}

func (s *stringSlice) Set(value string) error {
	// Allow "@" as a command that effectively does nothing but whose error (if any) is ignored.
	// An empty string after stripping "@" is handled in executeCommand.
	if value == "" {
		return fmt.Errorf("hook command cannot be empty (use '@' if a no-op with ignored error is intended)")
	}
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
	log.Printf("remoteconf version %s starting...", VERSION)

	urlFlag := flag.String("url", "", "Remote config data JSON file URL")
	var fileFlags stringSlice
	flag.Var(&fileFlags, "file", "Local config file to update (id=path). Must exist. Can be used multiple times.")
	var updateFlags stringSlice
	flag.Var(&updateFlags, "update", "Rules to update local files (<file-id>.<key>=<content-template>). Can be used multiple times.")

	var preHookFlags stringSlice
	flag.Var(&preHookFlags, "pre", "Global pre-update command or <file-id>=<cmd>. Prefix with '@' to ignore errors. Can be used multiple times.")
	var postHookFlags stringSlice
	flag.Var(&postHookFlags, "post", "Global post-update command or <file-id>=<cmd>. Prefix with '@' to ignore errors. Can be used multiple times.")

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

	localFiles := make(fileMap)
	for _, f := range fileFlags {
		parts := strings.SplitN(f, "=", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			log.Fatalf("Error: invalid 'file' flag format: %s. Expected 'id=path'", f)
		}
		localFiles[parts[0]] = parts[1]
		log.Printf("Registered local file: ID='%s', Path='%s'", parts[0], parts[1])
	}

	globalPreHooks, filePreHooks := parseHookFlags(preHookFlags, localFiles, "pre-hook")
	globalPostHooks, filePostHooks := parseHookFlags(postHookFlags, localFiles, "post-hook")

	if len(globalPreHooks) > 0 {
		log.Println("Executing global pre-update hooks...")
		for _, cmdStr := range globalPreHooks {
			runErr, ignoreCmdError := executeCommand(cmdStr, "Global pre-hook")
			if runErr != nil {
				if ignoreCmdError {
					log.Printf("Warning: Global pre-hook '%s' failed but error was ignored as requested: %v", cmdStr, runErr)
				} else {
					log.Fatalf("Error executing global pre-hook '%s': %v. Aborting.", cmdStr, runErr)
				}
			}
		}
		log.Println("Global pre-update hooks executed successfully.")
	}

	remoteConfig, err := fetchRemoteConfig(*urlFlag)
	if err != nil {
		log.Fatalf("Error fetching remote config from %s: %v", *urlFlag, err)
	}
	log.Printf("Successfully fetched remote config from %s", *urlFlag)

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
			FileID: fileID, Path: keyParts[1:], Template: tmpl, RawContent: parts[1],
		})
	}

	for fileID, filePath := range localFiles {
		log.Printf("Processing file: ID='%s', Path='%s'", fileID, filePath)
		err := processFile(fileID, filePath, remoteConfig, rules, filePreHooks[fileID], filePostHooks[fileID])
		if err != nil {
			log.Printf("Error processing file %s (ID: %s): %v", filePath, fileID, err)
		}
	}

	if len(globalPostHooks) > 0 {
		log.Println("Executing global post-update hooks...")
		for _, cmdStr := range globalPostHooks {
			runErr, ignoreCmdError := executeCommand(cmdStr, "Global post-hook")
			if runErr != nil {
				if ignoreCmdError {
					log.Printf("Note: Global post-hook '%s' failed but error was ignored as requested: %v", cmdStr, runErr)
				} else {
					log.Printf("Warning: Error executing global post-hook '%s': %v", cmdStr, runErr)
				}
			}
		}
		log.Println("Global post-update hooks executed successfully.")
	}

	log.Printf("remoteconf version %s execution finished.", VERSION)
}

func parseHookFlags(hookFlags []string, localFiles fileMap, hookTypeForLog string) (globalHooks []string, fileHooks map[string][]string) {
	fileHooks = make(map[string][]string)
	for _, hookCmdFull := range hookFlags {
		parts := strings.SplitN(hookCmdFull, "=", 2)
		commandPart := hookCmdFull // Default to full string for global or if malformed
		isFileSpecific := false
		var fileID string

		if len(parts) == 2 {
			potentialFileID := parts[0]
			// Check if potentialFileID is indeed a registered file ID
			if _, ok := localFiles[potentialFileID]; ok {
				// Also ensure it's not an empty fileID like "=cmd" or "@=cmd"
				if potentialFileID != "" && !(strings.HasPrefix(potentialFileID, "@") && strings.TrimPrefix(potentialFileID, "@") == "") {
					fileID = potentialFileID
					commandPart = parts[1] // The actual command line
					isFileSpecific = true
				}
			}
		}

		actualCommand := commandPart
		// Check for empty command *after* stripping potential fileID and @
		cleanedCommandForEmptyCheck := actualCommand
		if strings.HasPrefix(cleanedCommandForEmptyCheck, "@") {
			cleanedCommandForEmptyCheck = strings.TrimPrefix(cleanedCommandForEmptyCheck, "@")
		}
		if cleanedCommandForEmptyCheck == "" {
			log.Fatalf("Error: empty command line for %s '%s' (after parsing fileID and/or '@')", hookTypeForLog, hookCmdFull)
		}

		if isFileSpecific {
			fileHooks[fileID] = append(fileHooks[fileID], actualCommand) // Store command with '@' if present
			log.Printf("Registered file-specific %s for ID '%s': %s", hookTypeForLog, fileID, actualCommand)
		} else {
			globalHooks = append(globalHooks, hookCmdFull) // Store full command with '@' if present
			log.Printf("Registered global %s: %s", hookTypeForLog, hookCmdFull)
		}
	}
	return
}

func executeCommand(rawCommandStr string, hookDesc string) (err error, ignoreError bool) {
	commandToExecute := rawCommandStr
	if strings.HasPrefix(rawCommandStr, "@") {
		ignoreError = true
		commandToExecute = strings.TrimPrefix(rawCommandStr, "@")
		// No log here, caller can log if error occurs + is ignored
	}

	if commandToExecute == "" {
		log.Printf("Note: %s '%s' resulted in an empty command after stripping '@'. Skipping execution.", hookDesc, rawCommandStr)
		return nil, ignoreError // Nothing to run
	}

	log.Printf("Shell-parsing %s string: %s", hookDesc, commandToExecute)
	parts, shlexErr := shlex.Split(commandToExecute)
	if shlexErr != nil {
		return fmt.Errorf("failed to parse command string for %s ('%s'): %w", hookDesc, commandToExecute, shlexErr), ignoreError
	}

	if len(parts) == 0 { // Should be caught by commandToExecute == "" if shlex.Split("") is nil
		log.Printf("Parsed %s string '%s' resulted in no executable command. Skipping.", hookDesc, commandToExecute)
		return nil, ignoreError
	}

	commandName := parts[0]
	var args []string
	if len(parts) > 1 {
		args = parts[1:]
	}

	log.Printf("Running %s: '%s' with arguments %v", hookDesc, commandName, args)
	cmd := exec.Command(commandName, args...)

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	runErr := cmd.Run()

	if runErr != nil && ignoreError {
		log.Printf("Note: %s '%s' failed but error was ignored as requested: %v", hookDesc, rawCommandStr, runErr)
	}
	return runErr, ignoreError
}

func fetchRemoteConfig(url string) (map[string]interface{}, error) {
	// ... (same as before)
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
	// ... (same as before, ensure json.Decoder.UseNumber() is present)
	content, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, "", err
		}
		return nil, nil, "", fmt.Errorf("failed to read file %s: %w", filePath, err)
	}

	var data map[string]interface{}
	ext := strings.ToLower(filepath.Ext(filePath))

	switch ext {
	case ".json":
		decoder := json.NewDecoder(bytes.NewReader(content))
		decoder.UseNumber()
		err = decoder.Decode(&data)
		if err != nil {
			return nil, content, ext, fmt.Errorf("failed to unmarshal JSON from %s: %w", filePath, err)
		}
	case ".yaml", ".yml":
		err = yaml.Unmarshal(content, &data)
		if err != nil {
			return nil, content, ext, fmt.Errorf("failed to unmarshal YAML from %s: %w", filePath, err)
		}
		if data == nil {
			data = make(map[string]interface{})
		}
	case ".toml":
		_, err = toml.Decode(string(content), &data)
		if err != nil {
			return nil, content, ext, fmt.Errorf("failed to unmarshal TOML from %s: %w", filePath, err)
		}
	default:
		return nil, content, ext, fmt.Errorf("unsupported file extension: %s for file %s", ext, filePath)
	}
	return data, content, ext, nil
}

func writeFile(filePath string, data map[string]interface{}, format string) error {
	// ... (same as before)
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

	err = os.WriteFile(filePath, newContent, 0644)
	if err != nil {
		return fmt.Errorf("failed to write file %s: %w", filePath, err)
	}
	return nil
}

func processFile(fileID string, filePath string, remoteConfig map[string]interface{}, allRules []updateRule,
	preHooksForFile []string, postHooksForFile []string) error {

	localData, originalRawContent, format, err := readFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("Error: Local config file %s (ID: %s) must exist but was not found. Skipping this file and its hooks.", filePath, fileID)
			return nil
		}
		return fmt.Errorf("could not read initial state of %s: %w", filePath, err)
	}

	modifiedData := deepCopyMap(localData)
	rulesAppliedAndCausedInMemoryChange := false

	fileSpecificRules := []updateRule{}
	for _, rule := range allRules {
		if rule.FileID == fileID {
			fileSpecificRules = append(fileSpecificRules, rule)
		}
	}

	if len(fileSpecificRules) == 0 && len(preHooksForFile) == 0 && len(postHooksForFile) == 0 {
		if len(fileSpecificRules) == 0 {
			log.Printf("No update rules for %s. File content will not change. File-specific hooks will not run.", filePath)
			return nil
		}
	}

	for _, rule := range fileSpecificRules {
		currentVal, originalType, found := getNestedValueAndType(modifiedData, rule.Path)
		if !found {
			log.Printf("Warning: Path '%s' not found in file %s (ID: %s). Cannot update. Skipping this rule.", strings.Join(rule.Path, "."), filePath, fileID)
			continue
		}
		var tplOutput bytes.Buffer
		if err := rule.Template.Execute(&tplOutput, remoteConfig); err != nil {
			log.Printf("Warning: Failed to execute template for rule (FileID: %s, Path: %v): %v. Skipping rule.", rule.FileID, rule.Path, err)
			continue
		}
		newValueStr := tplOutput.String()
		finalValue, errConv := convertToOriginalType(newValueStr, originalType, rule.Path)
		if errConv != nil {
			log.Printf("Warning: Type conversion for path '%s' in %s (ID: %s) failed: %v. Value: '%s'. Skipping rule.", strings.Join(rule.Path, "."), filePath, fileID, errConv, newValueStr)
			continue
		}
		if !reflect.DeepEqual(currentVal, finalValue) {
			setNestedValue(modifiedData, rule.Path, finalValue)
			log.Printf("  Applied update to %s: Path='%s', NewValue='%v' (Type: %T)", filePath, strings.Join(rule.Path, "."), finalValue, finalValue)
			rulesAppliedAndCausedInMemoryChange = true
		} else {
			log.Printf("  Skipped update (no change) for %s: Path='%s', Value='%v'", filePath, strings.Join(rule.Path, "."), finalValue)
		}
	}

	if !rulesAppliedAndCausedInMemoryChange && len(fileSpecificRules) > 0 { // only skip if rules were present but made no change
		log.Printf("No in-memory changes for %s based on update rules. File not modified. File-specific hooks will not run.", filePath)
		return nil
	}

	var updatedRawContent []byte
	var marshalErr error
	// ... (serialization logic remains same)
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

	// If there were no rules, but there are file-specific hooks,
	// we still need to check if the file would "change" (it wouldn't if no rules).
	// The primary condition for hooks is `normOriginal != normUpdated`.
	// If rulesAppliedAndCausedInMemoryChange is false AND len(fileSpecificRules)==0,
	// it implies the file cannot change due to this tool, so hooks shouldn't run unless forced by other logic (not the case here).
	// The current logic: if !rulesApplied... then return. If rulesApplied... then check normOriginal vs normUpdated.
	// This means if no rules, it returns early. If rules, but no effective change, it returns before hooks.
	// If rules AND effective change, then hooks run. This is correct.

	if normOriginal == normUpdated {
		log.Printf("Content for %s (ID: %s) is semantically the same after updates. File not written. File-specific hooks will not run.", filePath, fileID)
		return nil
	}

	if len(preHooksForFile) > 0 {
		log.Printf("File content for %s (ID: %s) will change. Executing pre-update hooks...", filePath, fileID)
		for i, cmdStr := range preHooksForFile {
			hookDesc := fmt.Sprintf("File-specific pre-hook #%d for ID '%s'", i+1, fileID)
			runErr, ignoreCmdError := executeCommand(cmdStr, hookDesc)
			if runErr != nil {
				if !ignoreCmdError { // Only fail if error is not ignored
					return fmt.Errorf("%s '%s' failed: %w. Aborting update for this file", hookDesc, cmdStr, runErr)
				}
				// If ignoreCmdError is true, the error is already logged by executeCommand
			}
		}
		log.Printf("File-specific pre-hooks for %s (ID: %s) executed successfully (or errors ignored).", filePath, fileID)
	}

	log.Printf("Writing updated file %s", filePath)
	if err := writeFile(filePath, modifiedData, format); err != nil {
		return fmt.Errorf("failed to write updated file %s: %w (post-hooks will not run)", filePath, err)
	}
	log.Printf("File %s (ID: %s) successfully updated.", filePath, fileID)

	if len(postHooksForFile) > 0 {
		log.Printf("Executing post-update hooks for changed file %s (ID: %s)...", filePath, fileID)
		for i, cmdStr := range postHooksForFile {
			hookDesc := fmt.Sprintf("File-specific post-hook #%d for ID '%s'", i+1, fileID)
			runErr, ignoreCmdError := executeCommand(cmdStr, hookDesc)
			if runErr != nil && !ignoreCmdError { // Log as warning if error is not ignored
				log.Printf("Warning: %s '%s' failed: %v", hookDesc, cmdStr, runErr)
			}
			// If ignoreCmdError is true, error already logged by executeCommand
		}
		log.Printf("File-specific post-hooks for %s (ID: %s) executed successfully (or errors ignored).", filePath, fileID)
	}
	return nil
}

// --- Helper functions (convertToOriginalType, setNestedValue, getNestedValueAndType, deepCopyMap, deepCopySlice) ---
// These remain the same as in the previous version. For brevity, they are not repeated here but should be included.
// Make sure they are present in your final .go file.
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
