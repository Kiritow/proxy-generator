# Nginx Config Generator for Proxy

Generate nginx `http` section config from more user-friendly json.

[acme.sh](https://github.com/acmesh-official/acme.sh) is suggested for certificate management.

## Install

```bash
git clone https://github.com/Kiritow/proxy-generator
cd proxy-generator
mkdir local
```

## Example Config

`local/config.json`. See section config keys below for more information.

```json
[
    {
        "server": "site.example.com",
        "cert": "*.example.com",
        "ip": "127.0.0.1",
        "port": 8080,
        "https": true,
        "ws": true,
        "wsurl": "/ws",
        "settings": {
            "client_max_body_size": "512m"
        }
    }
]
```

## Config keys

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
