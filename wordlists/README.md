# Bundled wordlist

`subdomains-top1million-5000.txt` holds the 5,000 most common subdomain labels.
It is embedded into the binary at build time and used for `active`/`both` mode
brute force when no `--wordlist` is given. Pass your own list with `-w` to
override it.

Source: SecLists (https://github.com/danielmiessler/SecLists),
`Discovery/DNS/subdomains-top1million-5000.txt`, MIT License, Copyright (c) 2018
Daniel Miessler.
