package main

import (
	"bytes"
	"encoding/csv"
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
	"text/template" // Standard Go text/template package

	"github.com/BurntSushi/toml"
	"github.com/Masterminds/sprig/v3" // Added for Sprig template functions
	"github.com/google/shlex"
	"gopkg.in/ini.v1"
	"gopkg.in/yaml.v3"
)

// VERSION defines the program version.
const VERSION = "v0.4.0" // New feature: Sprig template functions

// stringSlice ... (definition remains the same)
type stringSlice []string

func (s *stringSlice) String() string {
	return strings.Join(*s, ", ")
}
func (s *stringSlice) Set(value string) error {
	if value == "" {
		return fmt.Errorf("flag value cannot be empty (use '@' for hooks if a no-op with ignored error is intended)")
	}
	*s = append(*s, value)
	return nil
}

// fileMap ... (definition remains the same)
type fileMap map[string]string

// updateRule ... (definition remains the same)
type updateRule struct {
	FileID     string
	Path       []string
	Template   *template.Template
	RawContent string
}

// explicitFileTypesMap ... (definition remains the same)
var explicitFileTypes map[string]string

func isFlagPassed(name string) bool {
	// ... (same as v0.3.1)
	found := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

func parseCSVString(csvString string) ([]string, error) {
	// ... (same as v0.3.1)
	if csvString == "" {
		return nil, nil
	}

	r := csv.NewReader(strings.NewReader(csvString))
	fields, err := r.Read()
	if err != nil {
		if err == io.EOF {
			return nil, nil
		}
		return nil, fmt.Errorf("parsing CSV string: %w", err)
	}
	result := make([]string, 0, len(fields))
	for _, field := range fields {
		trimmed := strings.TrimSpace(field)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result, nil
}

func main() {
	// Define flags (same as v0.3.1)
	urlFlag := flag.String("url", "", "Remote config data JSON file URL (Env: REMOTECONF_URL)")
	dryRunFlag := flag.Bool("dry-run", false, "Output config file changes without updating files or running hooks (Env: REMOTECONF_DRY_RUN)")

	var fileFlags stringSlice
	flag.Var(&fileFlags, "file", "Local config file to update (id=path). Must exist. (Env: REMOTECONF_FILE as CSV). Can be used multiple times.")
	var updateFlags stringSlice
	flag.Var(&updateFlags, "update", "Rules to update local files (<file-id>.<key>=<content-template>). (Env: REMOTECONF_UPDATE as CSV). Can be used multiple times.")
	var preHookFlags stringSlice
	flag.Var(&preHookFlags, "pre", "Global pre-update command or <file-id>=<cmd>. Prefix with '@' to ignore errors. (Env: REMOTECONF_PRE as CSV). Can be used multiple times.")
	var postHookFlags stringSlice
	flag.Var(&postHookFlags, "post", "Global post-update command or <file-id>=<cmd>. Prefix with '@' to ignore errors. (Env: REMOTECONF_POST as CSV). Can be used multiple times.")
	var fileTypeFlags stringSlice
	flag.Var(&fileTypeFlags, "file-type", "Explicitly set file type (<file-id>=<type> e.g., myconf=json). Overrides extension. (Env: REMOTECONF_FILE_TYPE as CSV). Can be used multiple times.")

	flag.Parse()

	// Handle environment variables (same logic structure as v0.3.1)
	if !isFlagPassed("url") {
		envVal := os.Getenv("REMOTECONF_URL")
		if envVal != "" {
			*urlFlag = envVal
			log.Printf("Using URL from environment variable REMOTECONF_URL")
		}
	}

	if !isFlagPassed("dry-run") {
		envVal := os.Getenv("REMOTECONF_DRY_RUN")
		if envVal != "" {
			valLower := strings.ToLower(envVal)
			if valLower == "0" || valLower == "false" {
				*dryRunFlag = false
			} else {
				*dryRunFlag = true
			}
			log.Printf("Using dry-run setting from environment variable REMOTECONF_DRY_RUN: %v", *dryRunFlag)
		}
	}

	if envFiles := os.Getenv("REMOTECONF_FILE"); envFiles != "" {
		parts, err := parseCSVString(envFiles)
		if err != nil {
			log.Printf("Warning: Could not parse REMOTECONF_FILE as CSV ('%s'): %v. Skipping these values.", envFiles, err)
		} else if len(parts) > 0 {
			fileFlags = append(fileFlags, parts...)
			log.Printf("Added %d file entries from REMOTECONF_FILE", len(parts))
		}
	}
	if envUpdates := os.Getenv("REMOTECONF_UPDATE"); envUpdates != "" {
		parts, err := parseCSVString(envUpdates)
		if err != nil {
			log.Printf("Warning: Could not parse REMOTECONF_UPDATE as CSV ('%s'): %v. Skipping these values.", envUpdates, err)
		} else if len(parts) > 0 {
			updateFlags = append(updateFlags, parts...)
			log.Printf("Added %d update rule entries from REMOTECONF_UPDATE", len(parts))
		}
	}
	if envPreHooks := os.Getenv("REMOTECONF_PRE"); envPreHooks != "" {
		parts, err := parseCSVString(envPreHooks)
		if err != nil {
			log.Printf("Warning: Could not parse REMOTECONF_PRE as CSV ('%s'): %v. Skipping these values.", envPreHooks, err)
		} else if len(parts) > 0 {
			preHookFlags = append(preHookFlags, parts...)
			log.Printf("Added %d pre-hook entries from REMOTECONF_PRE", len(parts))
		}
	}
	if envPostHooks := os.Getenv("REMOTECONF_POST"); envPostHooks != "" {
		parts, err := parseCSVString(envPostHooks)
		if err != nil {
			log.Printf("Warning: Could not parse REMOTECONF_POST as CSV ('%s'): %v. Skipping these values.", envPostHooks, err)
		} else if len(parts) > 0 {
			postHookFlags = append(postHookFlags, parts...)
			log.Printf("Added %d post-hook entries from REMOTECONF_POST", len(parts))
		}
	}
	if envFileTypes := os.Getenv("REMOTECONF_FILE_TYPE"); envFileTypes != "" {
		parts, err := parseCSVString(envFileTypes)
		if err != nil {
			log.Printf("Warning: Could not parse REMOTECONF_FILE_TYPE as CSV ('%s'): %v. Skipping these values.", envFileTypes, err)
		} else if len(parts) > 0 {
			fileTypeFlags = append(fileTypeFlags, parts...)
			log.Printf("Added %d file-type entries from REMOTECONF_FILE_TYPE", len(parts))
		}
	}

	startupMsg := fmt.Sprintf("remoteconf version %s starting...", VERSION)
	if *dryRunFlag {
		startupMsg = fmt.Sprintf("remoteconf version %s starting... DRY-RUN MODE ENABLED", VERSION)
	}
	log.Println(startupMsg)

	if *urlFlag == "" {
		log.Fatal("Error: 'url' is required (either via -url flag or REMOTECONF_URL environment variable)")
	}
	if len(fileFlags) == 0 {
		log.Fatal("Error: at least one 'file' is required (either via -file flag or REMOTECONF_FILE environment variable)")
	}
	if len(updateFlags) == 0 {
		log.Fatal("Error: at least one 'update' rule is required (either via -update flag or REMOTECONF_UPDATE environment variable)")
	}

	localFiles := make(fileMap)
	for _, f := range fileFlags {
		parts := strings.SplitN(f, "=", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			log.Fatalf("Error: invalid 'file' entry format: '%s'. Expected 'id=path'", f)
		}
		localFiles[parts[0]] = parts[1]
		log.Printf("Registered local file: ID='%s', Path='%s'", parts[0], parts[1])
	}

	explicitFileTypes = make(map[string]string)
	for _, ft := range fileTypeFlags {
		parts := strings.SplitN(ft, "=", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			log.Fatalf("Error: invalid 'file-type' entry format: '%s'. Expected 'id=type'", ft)
		}
		fileID := parts[0]
		typeName := strings.ToLower(strings.TrimPrefix(parts[1], "."))

		if _, ok := localFiles[fileID]; !ok {
			log.Fatalf("Error: file ID '%s' in file-type '%s' not defined in any '-file' entry", fileID, ft)
		}
		switch typeName {
		case "json", "yaml", "yml", "toml", "ini":
			if typeName == "yml" {
				typeName = "yaml"
			}
			explicitFileTypes[fileID] = typeName
			log.Printf("Registered explicit file type for ID '%s': %s", fileID, typeName)
		default:
			log.Fatalf("Error: unsupported file type '%s' specified for file ID '%s' in file-type entry '%s'", parts[1], fileID, ft)
		}
	}

	globalPreHooks, filePreHooks := parseHookFlags(preHookFlags, localFiles, "pre-hook")
	globalPostHooks, filePostHooks := parseHookFlags(postHookFlags, localFiles, "post-hook")

	if !*dryRunFlag && len(globalPreHooks) > 0 {
		log.Println("Executing global pre-update hooks...")
		for _, cmdStr := range globalPreHooks {
			runErr, ignoreCmdError := executeCommand(cmdStr, "Global pre-hook")
			if runErr != nil {
				if !ignoreCmdError {
					log.Fatalf("Error executing global pre-hook '%s': %v. Aborting.", cmdStr, runErr)
				}
			}
		}
		log.Println("Global pre-update hooks executed successfully (or errors ignored).")
	} else if *dryRunFlag && len(globalPreHooks) > 0 {
		log.Println("DRY-RUN: Global pre-update hooks would be executed.")
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
			log.Fatalf("Error: invalid 'update' rule format: '%s'. Expected '<file-id>.<key>=<content-template>'", u)
		}
		keyParts := strings.Split(parts[0], ".")
		if len(keyParts) < 2 {
			log.Fatalf("Error: invalid key in 'update' rule: '%s'. Expected '<file-id>.<key.subkey...>'", parts[0])
		}
		fileID := keyParts[0]
		if _, ok := localFiles[fileID]; !ok {
			log.Fatalf("Error: file ID '%s' in update rule '%s' not defined in any '-file' entry", fileID, u)
		}

		// ** MODIFIED SECTION for Sprig functions **
		tmpl, err := template.New(parts[0]).Funcs(sprig.TxtFuncMap()).Parse(parts[1])
		if err != nil {
			log.Fatalf("Error parsing template (with Sprig) for rule '%s': %v", u, err)
		}
		// ** END MODIFIED SECTION **

		rules = append(rules, updateRule{
			FileID: fileID, Path: keyParts[1:], Template: tmpl, RawContent: parts[1],
		})
	}

	for fileID, filePath := range localFiles {
		log.Printf("Processing file: ID='%s', Path='%s'", fileID, filePath)
		determinedFormat, formatErr := determineFileFormat(filePath, fileID, explicitFileTypes)
		if formatErr != nil {
			log.Printf("Error determining file format for %s (ID: %s): %v. Skipping this file.", filePath, fileID, formatErr)
			continue
		}
		log.Printf("Determined format for %s (ID: %s): %s", filePath, fileID, determinedFormat)

		err := processFile(fileID, filePath, determinedFormat, remoteConfig, rules, filePreHooks[fileID], filePostHooks[fileID], *dryRunFlag)
		if err != nil {
			log.Printf("Error processing file %s (ID: %s): %v", filePath, fileID, err)
		}
	}

	if !*dryRunFlag && len(globalPostHooks) > 0 {
		log.Println("Executing global post-update hooks...")
		for _, cmdStr := range globalPostHooks {
			runErr, ignoreCmdError := executeCommand(cmdStr, "Global post-hook")
			if runErr != nil {
				if !ignoreCmdError {
					log.Printf("Warning: Error executing global post-hook '%s': %v", cmdStr, runErr)
				}
			}
		}
		log.Println("Global post-update hooks executed successfully (or errors ignored).")
	} else if *dryRunFlag && len(globalPostHooks) > 0 {
		log.Println("DRY-RUN: Global post-update hooks would be executed.")
	}

	log.Printf("remoteconf version %s execution finished.", VERSION)
}

// --- determineFileFormat, parseHookFlags, executeCommand, fetchRemoteConfig ---
// --- readFile, writeFile, processFile, convertToOriginalType, and other helpers ---
// These functions remain the same as v0.3.1 / v0.2.2.
// Ensure you have the correct versions of these from the previous iterations.
// For brevity, they are not repeated here but are essential for the program to function.

func determineFileFormat(filePath string, fileID string, explicitTypes map[string]string) (string, error) {
	if explicitType, ok := explicitTypes[fileID]; ok {
		return explicitType, nil
	}
	ext := strings.ToLower(strings.TrimPrefix(filepath.Ext(filePath), "."))
	switch ext {
	case "json", "yaml", "toml", "ini":
		return ext, nil
	case "yml":
		return "yaml", nil
	default:
		if ext == "" {
			return "", fmt.Errorf("file '%s' (ID: %s) has no extension and no explicit type was provided", filePath, fileID)
		}
		return "", fmt.Errorf("unsupported file extension '.%s' for file '%s' (ID: %s) and no explicit type provided", ext, filePath, fileID)
	}
}

func parseHookFlags(hookFlags []string, localFiles fileMap, hookTypeForLog string) (globalHooks []string, fileHooks map[string][]string) {
	fileHooks = make(map[string][]string)
	for _, hookCmdFull := range hookFlags {
		parts := strings.SplitN(hookCmdFull, "=", 2)
		commandPart := hookCmdFull
		isFileSpecific := false
		var fileID string

		if len(parts) == 2 {
			potentialFileID := parts[0]
			if _, ok := localFiles[potentialFileID]; ok && potentialFileID != "" {
				fileID = potentialFileID
				commandPart = parts[1]
				isFileSpecific = true
			}
		}

		cleanedCommandForEmptyCheck := commandPart
		if strings.HasPrefix(cleanedCommandForEmptyCheck, "@") {
			cleanedCommandForEmptyCheck = strings.TrimPrefix(cleanedCommandForEmptyCheck, "@")
		}
		if cleanedCommandForEmptyCheck == "" {
			log.Fatalf("Error: empty command line for %s '%s' (after parsing fileID and/or '@')", hookTypeForLog, hookCmdFull)
		}

		if isFileSpecific {
			fileHooks[fileID] = append(fileHooks[fileID], commandPart)
			log.Printf("Registered file-specific %s for ID '%s': %s", hookTypeForLog, fileID, commandPart)
		} else {
			globalHooks = append(globalHooks, hookCmdFull)
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
	}

	if commandToExecute == "" {
		log.Printf("Note: %s '%s' resulted in an empty command after stripping '@'. Skipping execution.", hookDesc, rawCommandStr)
		return nil, ignoreError
	}

	log.Printf("Shell-parsing %s string: %s", hookDesc, commandToExecute)
	parts, shlexErr := shlex.Split(commandToExecute)
	if shlexErr != nil {
		return fmt.Errorf("failed to parse command string for %s ('%s'): %w", hookDesc, commandToExecute, shlexErr), ignoreError
	}

	if len(parts) == 0 {
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

var jsonNumberType = reflect.TypeOf(json.Number(""))

func readFile(filePath string, format string) (data map[string]interface{}, rawContent []byte, err error) {
	rawContent, err = os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, err
		}
		return nil, nil, fmt.Errorf("failed to read file %s: %w", filePath, err)
	}

	data = make(map[string]interface{})

	switch format {
	case "json":
		decoder := json.NewDecoder(bytes.NewReader(rawContent))
		decoder.UseNumber()
		if decErr := decoder.Decode(&data); decErr != nil {
			return nil, rawContent, fmt.Errorf("failed to unmarshal JSON from %s: %w", filePath, decErr)
		}
	case "yaml":
		if yamlErr := yaml.Unmarshal(rawContent, &data); yamlErr != nil {
			return nil, rawContent, fmt.Errorf("failed to unmarshal YAML from %s: %w", filePath, yamlErr)
		}
		if data == nil {
			data = make(map[string]interface{})
		}
	case "toml":
		if tomlErr := toml.Unmarshal(rawContent, &data); tomlErr != nil {
			return nil, rawContent, fmt.Errorf("failed to unmarshal TOML from %s: %w", filePath, tomlErr)
		}
	case "ini":
		iniFile, iniErr := ini.LoadSources(ini.LoadOptions{
			AllowBooleanKeys: true,
		}, rawContent)
		if iniErr != nil {
			return nil, rawContent, fmt.Errorf("failed to load INI data from %s: %w", filePath, iniErr)
		}
		for _, section := range iniFile.Sections() {
			sectionName := section.Name()
			if sectionName == ini.DEFAULT_SECTION && len(section.Keys()) == 0 {
				continue
			}

			sectionMap := make(map[string]interface{})
			for _, key := range section.Keys() {
				sectionMap[key.Name()] = key.String()
			}
			data[sectionName] = sectionMap
		}
	default:
		return nil, rawContent, fmt.Errorf("readFile: unsupported format '%s' for file %s", format, filePath)
	}
	return data, rawContent, nil
}

func writeFile(filePath string, data map[string]interface{}, format string) error {
	var newContent []byte
	var err error

	switch format {
	case "json":
		newContent, err = json.MarshalIndent(data, "", "  ")
	case "yaml":
		newContent, err = yaml.Marshal(data)
	case "toml":
		var buf bytes.Buffer
		encoder := toml.NewEncoder(&buf)
		if encErr := encoder.Encode(data); encErr != nil {
			return fmt.Errorf("failed to marshal TOML for %s: %w", filePath, encErr)
		}
		newContent = buf.Bytes()
	case "ini":
		iniFile := ini.Empty()
		for sectionName, sectionUntyped := range data {
			sectionData, ok := sectionUntyped.(map[string]interface{})
			if !ok {
				log.Printf("Warning: converting data to INI for %s: top-level key '%s' is not a section (map[string]interface{}); skipping.", filePath, sectionName)
				continue
			}

			var iniSection *ini.Section
			iniSection, err = iniFile.NewSection(sectionName)
			if err != nil {
				return fmt.Errorf("failed to create INI section '%s' for %s: %w", sectionName, filePath, err)
			}

			for key, value := range sectionData {
				_, keyErr := iniSection.NewKey(key, fmt.Sprintf("%v", value))
				if keyErr != nil {
					return fmt.Errorf("failed to create INI key '%s' in section '%s' for %s: %w", key, sectionName, filePath, keyErr)
				}
			}
		}
		var buf bytes.Buffer
		_, err = iniFile.WriteTo(&buf)
		if err == nil {
			newContent = buf.Bytes()
		}

	default:
		return fmt.Errorf("writeFile: unsupported format '%s' for writing", format)
	}

	if err != nil {
		return fmt.Errorf("failed to prepare content for %s (format %s): %w", filePath, format, err)
	}

	return os.WriteFile(filePath, newContent, 0644)
}

func processFile(fileID string, filePath string, format string, remoteConfig map[string]interface{}, allRules []updateRule,
	preHooksForFile []string, postHooksForFile []string, dryRun bool) error {
	localData, originalRawContent, err := readFile(filePath, format)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("Error: Local config file %s (ID: %s) must exist but was not found. Skipping.", filePath, fileID)
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

	for _, rule := range fileSpecificRules {
		currentVal, _, found := getNestedValueAndType(modifiedData, rule.Path)
		if !found {
			log.Printf("Warning: Path '%s' not found in file %s (ID: %s, Format: %s). Cannot update. Skipping this rule.", strings.Join(rule.Path, "."), filePath, fileID, format)
			continue
		}
		var tplOutput bytes.Buffer
		if err := rule.Template.Execute(&tplOutput, remoteConfig); err != nil {
			log.Printf("Warning: Failed to execute template for rule (FileID: %s, Path: %v): %v. Skipping rule.", rule.FileID, rule.Path, err)
			continue
		}
		newValueStr := tplOutput.String()
		finalValue, errConv := convertToOriginalType(newValueStr, currentVal, rule.Path)
		if errConv != nil {
			log.Printf("Warning: Type conversion for path '%s' in %s (ID: %s) failed: %v. Value from template: '%s'. Skipping rule.", strings.Join(rule.Path, "."), filePath, fileID, errConv, newValueStr)
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

	if !rulesAppliedAndCausedInMemoryChange && len(fileSpecificRules) > 0 {
		log.Printf("No in-memory changes for %s (ID: %s) based on update rules. File will not be modified.", filePath, fileID)
		return nil
	}
	if len(fileSpecificRules) == 0 {
		log.Printf("No update rules for %s (ID: %s). File content unchanged by rules.", filePath, fileID)
	}

	var updatedRawContent []byte
	var marshalErr error
	switch format {
	case "json":
		updatedRawContent, marshalErr = json.MarshalIndent(modifiedData, "", "  ")
	case "yaml":
		updatedRawContent, marshalErr = yaml.Marshal(modifiedData)
	case "toml":
		var buf bytes.Buffer
		encoder := toml.NewEncoder(&buf)
		marshalErr = encoder.Encode(modifiedData)
		if marshalErr == nil {
			updatedRawContent = buf.Bytes()
		}
	case "ini":
		iniFile := ini.Empty()
		for sectionName, sectionUntyped := range modifiedData {
			sectionData, ok := sectionUntyped.(map[string]interface{})
			if !ok {
				log.Printf("Warning: converting data to INI for %s: top-level key '%s' is not a section (map[string]interface{}); skipping.", filePath, sectionName)
				continue
			}
			var iniSection *ini.Section
			var secCreateErr error
			iniSection, secCreateErr = iniFile.NewSection(sectionName)
			if secCreateErr != nil {
				marshalErr = fmt.Errorf("failed to create INI section '%s': %w", sectionName, secCreateErr)
				break
			}
			for key, value := range sectionData {
				_, keyErr := iniSection.NewKey(key, fmt.Sprintf("%v", value))
				if keyErr != nil {
					marshalErr = fmt.Errorf("failed to create INI key '%s' in section '%s': %w", key, sectionName, keyErr)
					break
				}
			}
			if marshalErr != nil {
				break
			}
		}
		if marshalErr == nil {
			var buf bytes.Buffer
			_, marshalErr = iniFile.WriteTo(&buf)
			if marshalErr == nil {
				updatedRawContent = buf.Bytes()
			}
		}
	default:
		return fmt.Errorf("processFile: unsupported format '%s' for marshalling", format)
	}

	if marshalErr != nil {
		return fmt.Errorf("failed to marshal modified data for %s (format %s): %w", filePath, format, marshalErr)
	}

	normOriginal := strings.TrimSpace(string(originalRawContent))
	normUpdated := strings.TrimSpace(string(updatedRawContent))

	if normOriginal == normUpdated {
		log.Printf("Content for %s (ID: %s) is semantically the same after updates or no rules applied. File not written. File-specific hooks will not run.", filePath, fileID)
		return nil
	}

	if dryRun {
		log.Printf("DRY-RUN: File %s (ID: %s) would be updated.", filePath, fileID)
		fmt.Printf("\n--- DRY-RUN: Start of changes for %s (ID: %s) ---\n", filePath, fileID)
		fmt.Print(string(updatedRawContent))
		fmt.Printf("\n--- DRY-RUN: End of changes for %s (ID: %s) ---\n\n", filePath, fileID)
		if len(preHooksForFile) > 0 || len(postHooksForFile) > 0 {
			log.Printf("DRY-RUN: File-specific hooks for %s (ID: %s) would be ignored.", filePath, fileID)
		}
		return nil
	}

	if len(preHooksForFile) > 0 {
		log.Printf("File content for %s (ID: %s) will change. Executing pre-update hooks...", filePath, fileID)
		for i, cmdStr := range preHooksForFile {
			hookDesc := fmt.Sprintf("File-specific pre-hook #%d for ID '%s'", i+1, fileID)
			runErr, ignoreCmdError := executeCommand(cmdStr, hookDesc)
			if runErr != nil && !ignoreCmdError {
				return fmt.Errorf("%s '%s' failed: %w. Aborting update for this file", hookDesc, cmdStr, runErr)
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
			if runErr != nil && !ignoreCmdError {
				log.Printf("Warning: %s '%s' failed: %v", hookDesc, cmdStr, runErr)
			}
		}
		log.Printf("File-specific post-hooks for %s (ID: %s) executed successfully (or errors ignored).", filePath, fileID)
	}
	return nil
}

func convertToOriginalType(newValueStr string, originalVal interface{}, path []string) (interface{}, error) {
	if strings.ToLower(newValueStr) == "null" {
		return nil, nil
	}

	if originalVal == nil {
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

	originalType := reflect.TypeOf(originalVal)

	if originalType == jsonNumberType {
		if iVal, err := strconv.ParseInt(newValueStr, 10, 64); err == nil {
			return iVal, nil
		}
		if fVal, err := strconv.ParseFloat(newValueStr, 64); err == nil {
			return fVal, nil
		}
		return nil, fmt.Errorf("value '%s' from template is not a valid number format for original numeric field at path %v", newValueStr, path)
	}

	switch originalType.Kind() {
	case reflect.String:
		return newValueStr, nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		iVal, err := strconv.ParseInt(newValueStr, 10, originalType.Bits())
		if err != nil {
			if fVal, fErr := strconv.ParseFloat(newValueStr, 64); fErr == nil {
				iValFromFloat := int64(fVal)
				if val := reflect.New(originalType).Elem(); val.OverflowInt(iValFromFloat) {
					return nil, fmt.Errorf("value '%s' (parsed as float %f, int %d) overflows original integer type %s for path %v", newValueStr, fVal, iValFromFloat, originalType.Kind(), path)
				}
				if float64(iValFromFloat) == fVal {
					val := reflect.New(originalType).Elem()
					val.SetInt(iValFromFloat)
					return val.Interface(), nil
				}
			}
			return nil, fmt.Errorf("cannot convert '%s' to original integer type %s for path %v: %w", newValueStr, originalType.Kind(), path, err)
		}
		val := reflect.New(originalType).Elem()
		val.SetInt(iVal)
		return val.Interface(), nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		uVal, err := strconv.ParseUint(newValueStr, 10, originalType.Bits())
		if err != nil {
			if fVal, fErr := strconv.ParseFloat(newValueStr, 64); fErr == nil && fVal >= 0 {
				uValFromFloat := uint64(fVal)
				if val := reflect.New(originalType).Elem(); val.OverflowUint(uValFromFloat) {
					return nil, fmt.Errorf("value '%s' (parsed as float %f, uint %d) overflows original unsigned integer type %s for path %v", newValueStr, fVal, uValFromFloat, originalType.Kind(), path)
				}
				if float64(uValFromFloat) == fVal {
					val := reflect.New(originalType).Elem()
					val.SetUint(uValFromFloat)
					return val.Interface(), nil
				}
			}
			return nil, fmt.Errorf("cannot convert '%s' to original unsigned integer type %s for path %v: %w", newValueStr, originalType.Kind(), path, err)
		}
		val := reflect.New(originalType).Elem()
		val.SetUint(uVal)
		return val.Interface(), nil
	case reflect.Float32, reflect.Float64:
		fVal, err := strconv.ParseFloat(newValueStr, originalType.Bits())
		if err != nil {
			return nil, fmt.Errorf("cannot convert '%s' to original float type %s for path %v: %w", newValueStr, originalType.Kind(), path, err)
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
		return nil, fmt.Errorf("unsupported original type %s for automatic conversion at path %v. Value from template: '%s'", originalType.Kind(), path, newValueStr)
	}
}

func setNestedValue(data map[string]interface{}, path []string, value interface{}) {
	current := data
	for i, key := range path {
		if i == len(path)-1 {
			current[key] = value
			return
		}
		if _, ok := current[key]; !ok {
			current[key] = make(map[string]interface{})
		}
		if nextMap, ok := current[key].(map[string]interface{}); ok {
			current = nextMap
		} else {
			log.Printf("Warning: Overwriting non-map value at path segment '%s' to set nested key '%s'", strings.Join(path[:i+1], "."), strings.Join(path, "."))
			newMap := make(map[string]interface{})
			current[key] = newMap
			current = newMap
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
	if len(path) == 0 && data != nil {
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
