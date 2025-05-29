# remoteconf

By Gemini 2.5 Pro AI.

- [remoteconf](#remoteconf)
  - [Prompt](#prompt)
    - [Initial prompt](#initial-prompt)
    - [Follow-up prompts](#follow-up-prompts)
    - [v0.2.2](#v022)
    - [v0.3.1](#v031)
  - [Flags](#flags)

## Prompt

### Initial prompt

> Write a Go program "remoteconf", which is used to fetch config data from remote and apply them to local files dynamically.
>
> When program runned, fetch "config data" json from a http url, then update local config files.
>
> The program accept several cmd flags:
>
> - "url" : Remote "config data" json file url.
> - "file" : local config file to update. Can be used several >times. Each one has `id=path` format. Config file could be in json, yaml, or toml format, determined by extension.
> - "update" : Rules to update local files. Can be used several times. Each one has `<key>=<content>` format. `<key>` is the property key(s) in config file, joined by ".", with `<file-id>.` prefix. `<content>` is the updated content Go text template, with the "config data" fetched from remote as context.
>
> E.g.
>
> ```
> remoteconf -url "https://example.com/config.json" -file "foo=/etc/foo.json" -update "foo.server={{.addr}}" -update "foo.server_port={{.port}}"
> ```
>
> Saying the contents of "https://example.com/config.json" is :

> ```
> {
>  "addr": "192.168.1.1",
>  "port": 22
> }
> ```
>
> The current contents of "/etc/foo.json" file:
>
> ```
> {
>  "server": "",
>  "server_port": 0
> }
> ```
>
> After the program executed, the contents of "/etc/foo.json" should be:
>
> ```
> {
>  "server": "192.168.1.1",
>  "server_port": 22
> }
> ```
>
> Note: it should only update local files if the new file contents is different from the current one.

### Follow-up prompts

> Make the follow changes:
>
> 1.  The local config file must already exist. The program is only used to update local config files, not create them. Also, the updated field value should have the same type as previous one. E.g. the "server_port" field will be set to 22 instead of "22" because the previous value is a number instead of a string.
> 2.  Add optional "pre" and "post" flags, which is the custom cmdline that will be executed before / after modifying local config files.

> The cmdline of pre / post hooks should be executed directly instead of executed by cmd / sh. Use shlex ( https://pkg.go.dev/github.com/google/shlex ) or similar package to parse cmdline

> Enhance the pre / post hooks that:
>
> - Accept multiple pre / post hooks
> - It's possible to use `<file-id>=<cmdline>` syntax in hook. Which is only getting executed before / after the target config file being updated. Note: If the contents of a config file don't change, it's hooks won't be executed.

> Make the follow changes:
>
> 1.  If a cmdline of pre / post hooks has a leading "@" char, ignore any error when executing it.
> 2.  Add a VERSION constant which define the version number of the program. Set it to "v0.1.0". Print the program verison when program started. The future changes to program codes should update the VERSION constant according to Semantic Versioning rules.

> Add a optional "dry-run" boolean flag, which makes the program only output config file changes without actually updating them. The hooks are also ignored in this mode.

> Make the follow changes:
>
> - Add optional "file-type" flag, which uses `<file-id>=<type>` syntax. The flag can be used to explicitly set the config file type (json / toml / yaml /...).
> - Support .ini file type. Use https://pkg.go.dev/gopkg.in/ini.v1 , https://pkg.go.dev/github.com/go-ini/ini or similar package.

### v0.2.2

```
I found a bug that the updated value in config file doesn't follow it's previous type. E.g. if the current "server_port" value is 22 (number), the new value (Go text template render result) is "23", it will update the config file field to "23" (string). But I want the new value to be 23 (number)
```

### v0.3.1

```
Improve the program to make it be able to read all options from environment variables.
Prefix env variable names with "REMOTECONF".
E.g. the "file-type" flag can be set via "REMOTECONF_FILE_TYPE" env variable.
For flags of stringSlice type, the env variable value is treated as a CSV string.
For flags of boolean type, any non-empty environment variable value, except "0" and "false", is treated as true.

For stringSlice options, if both cmdling flags and environment variables are defined, all values will be used.
For other type option, cmdline flags take precedence over environment variables.
```

```
Use "encoding/csv" package to parse csv value instead of just strings.Split(csvString, ",") , which doesn't handle escaping / quoting at all.
```

## Flags

```
Usage of remoteconf:
  -dry-run
        Output config file changes without updating files or running hooks (Env: REMOTECONF_DRY_RUN)
  -file value
        Local config file to update (id=path). Must exist. (Env: REMOTECONF_FILE as CSV). Can be used multiple times.
  -file-type value
        Explicitly set file type (<file-id>=<type> e.g., myconf=json). Overrides extension. (Env: REMOTECONF_FILE_TYPE as CSV). Can be used multiple times.
  -post value
        Global post-update command or <file-id>=<cmd>. Prefix with '@' to ignore errors. (Env: REMOTECONF_POST as CSV). Can be used multiple times.
  -pre value
        Global pre-update command or <file-id>=<cmd>. Prefix with '@' to ignore errors. (Env: REMOTECONF_PRE as CSV). Can be used multiple times.
  -update value
        Rules to update local files (<file-id>.<key>=<content-template>). (Env: REMOTECONF_UPDATE as CSV). Can be used multiple times.
  -url string
        Remote config data JSON file URL (Env: REMOTECONF_URL)
```
