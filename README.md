# remoteconf

By Gemini 2.5 Pro AI.

## Prompt

Write a Go program "remoteconf", which is used to fetch config data from remote and apply them to local files dynamically.

When program runned, fetch "config data" json from a http url, then update local config files.

The program accept several cmd flags:

- "url" : Remote "config data" json file url.
- "file" ： local config file to update. Can be used several times. Each one has `id=path` format. Config file could be in json, yaml, or toml format, determined by extension.
- "update" : Rules to update local files. Can be used several times. Each one has `<key>=<content>` format. `<key>` is the property key(s) in config file, joined by ".", with `<file-id>.` prefix. `<content>` is the updated content Go text template, with the "config data" fetched from remote as context.

E.g.

```
remoteconf -url "https://example.com/config.json" -file "foo=/etc/foo.json" -update "foo.server={{.addr}}" -update "foo.server_port={{.port}}"
```

Saying the contents of "https://example.com/config.json" is :

```
{
  "addr": "192.168.1.1",
  "port": 22
}
```

The current contents of "/etc/foo.json" file:

```
{
  "server": "",
  "server_port": 0
}
```

After the program executed, the contents of "/etc/foo.json" should be:

```
{
  "server": "192.168.1.1",
  "server_port": 22
}
```

Note: it should only update local files, if the new file contents is different from the current one.
