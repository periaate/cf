# dns
Automatically updates the (first) A record of the configured Cloudflare domain.

## Environment variables
`dns` requires three env variables to be set:

`CF_API` - Your API token.\
`CF_ZONE` - Your zone id.\
`CF_DOMAIN` - Your domain name.\

See my other project, [envi](https://github.com/periaate/envi), which was designed for safe storage and injection of such env variables.