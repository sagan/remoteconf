# remoteconf

By Gemini 2.5 Pro AI.

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
