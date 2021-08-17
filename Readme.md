# Nginx Config Generator for Proxy

`server`: Domain Name

`type`: Config type, default to `proxy`. Available options: `proxy`, `prefix`

`ip`: Upstream ip, default to `127.0.0.1`

`port`: Upstream port

`http`: Enable HTTP support, default to `true` if https is not enabled. Otherwise, `false`

`https`: Enable HTTPS support, default to `false`

`cert`: Cert name. Default to domain name.

`gzip`: Enable GZip-Compression, default to `false`

`ws`: Enable websocket support, default to `false`

`wsurl`: Websocket URL, default to `/`

`settings`: Custom nginx config, default to `[]`
