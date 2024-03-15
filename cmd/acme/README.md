# acme
`acme` tries to refresh TLS certificates for the configured domain.

## Environment variables
`acme` requires three env variables to be set:

`CA_EMAIL` - The email you want to use for your CA registration.\
`CF_AUTH` - Your Cloudflare API token (needs permissions to do `DNS-01` challenges).\
`CF_DOMAIN` - Your domain name.\

See my other project, [envi](https://github.com/periaate/envi), which was designed for safe storage and injection of such env variables.

## Flags
`-t --tlsdir` - Filepath to the directory you have, or want to have, your `cert.pem` and `key.pem` files. Defaults to current working directory.