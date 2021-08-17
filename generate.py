# -*- coding: utf-8 -*-
import os
import time
import json


ACME_ROOT = "/home/{}/.acme.sh".format(os.getenv("USER"))


def get_default_location(path, local_addr, local_port, extra_configs=None):
    conf = {
        "path": "^~ {}".format(path),
        "configs": [{
            "key": "add_header",
            "value": "X-Served-By $host",
        }, {
            "key": "proxy_set_header",
            "value": "Host $host",
        }, {
            "key": "proxy_set_header",
            "value": "X-Forwarded-Scheme $scheme",
        }, {
            "key": "proxy_set_header",
            "value": "X-Forwarded-Proto $scheme",
        }, {
            "key": "proxy_set_header",
            "value": "X-Forwarded-For $remote_addr",
        }, {
            "key": "proxy_set_header",
            "value": "X-Real-IP $remote_addr",
        }, {
            "key": "proxy_set_header",
            "value": "X-Real-Port $remote_port",
        }, {
            "key": "proxy_pass",
            "value": "http://{}:{}".format(local_addr, local_port)
        }]
    }

    if extra_configs:
        conf["configs"].extend(extra_configs)

    return conf


def get_gzip_options():
    return [{
        "key": "gzip",
        "value": "on",
    }, {
        "key": "gzip_disable",
        "value": "msie6",
    }, {
        "key": "gzip_vary",
        "value": "on",
    }, {
        "key": "gzip_proxied",
        "value": "any",
    }, {
        "key": "gzip_comp_level",
        "value": "6",
    }, {
        "key": "gzip_buffers",
        "value": "4 16k",
    }, {
        "key": "gzip_http_version",
        "value": "1.1",
    }, {
        "key": "gzip_types",
        "value": "application/atom+xml application/javascript application/x-javascript application/json application/rss+xml application/vnd.ms-fontobject application/x-font application/x-font-opentype application/x-font-otf application/x-font-truetype application/x-font-ttf application/x-web-app-manifest+json application/xhtml+xml application/xml font/opentype font/otf font/ttf image/svg+xml image/x-icon text/css text/plain text/javascript text/x-component text/xml",
    }]


def servers_to_nginx(servers):
    output = ["# Auto generated at {}".format(time.strftime("%Y-%m-%d %H:%M:%S"))]
    for this_server in servers:
        output.extend([
            "server {",
            "  server_name {};".format(this_server["server"])
        ])
        for item in this_server["configs"]:
            output.append("  {} {};".format(item["key"], item["value"]))
        for this_location in this_server["locations"]:
            output.append("  location {} {{".format(this_location["path"]))
            for item in this_location["configs"]:
                output.append("    {} {};".format(item["key"], item["value"]))
            output.append("  }")
        output.extend(["}", ""])

    return '\n'.join(output)


def parse_configs(configs):
    servers = []

    for config in configs:
        if not config.get("enable", True):
            continue

        server_name = config["server"]
        custom_settings = config.get("settings", [])
        custom_locations = config.get("locations", [])

        config_type = config.get("type", "proxy")
        if config_type == "prefix":
            this_server = {
                "server": "~^(.+)?{}".format(".{}".format(server_name).replace('.', '\\.')),
                "locations": [],
                "configs": [{"key": key, "value": custom_settings[key]} for key in custom_settings] + [{
                    "key": "return",
                    "value": "301 https://$host$request_uri"
                }]
            }
            servers.append(this_server)  # prefix-https-redirect
            continue

        local_port = config["port"]
        local_ip = config.get("ip", "127.0.0.1")

        enable_compression = config.get("gzip", False)

        cert_name = config.get("cert", server_name)  # wildcard certs should be specified here.
        enable_https = config.get("https", False)
        if enable_https:
            enable_http = config.get("http", False)
        else:
            enable_http = config.get("http", True)
        if not enable_https and not enable_http:
            raise Exception("HTTP/HTTPS not enabled. Please check config for {}".format(server_name))

        enable_websocket = config.get("ws", False)
        if enable_websocket:
            websocket_path = config.get("wsurl", "/")
        else:
            websocket_path = None

        this_server = {
            "server": server_name,
            "configs": [{"key": key, "value": custom_settings[key]} for key in custom_settings],
            "locations": [get_default_location("/", local_ip, local_port)]
        }

        if not enable_http:
            this_server["locations"] = []
            this_server["configs"].append({
                "key": "return",
                "value": "301 https://$host$request_uri"
            })
        
        if enable_http and enable_compression:
            this_server["configs"].extend(get_gzip_options())

        servers.append(this_server)  # http

        if enable_https:
            ssl_configs = [{
               "key": "listen",
               "value": "443 ssl"
            }, {
                "key": "ssl_certificate",
                "value": "{}/{}/fullchain.cer".format(ACME_ROOT, cert_name),
            }, {
                "key": "ssl_certificate_key",
                "value": "{}/{}/{}.key".format(ACME_ROOT, cert_name, cert_name),
            }, {
                "key": "ssl_session_timeout",
                "value": "1d",
            },  {
                "key": "ssl_session_cache",
                "value": "shared:MozSSL:10m",
            }, {
                "key": "ssl_session_tickets",
                "value": "off",
            }, {
                "key": "ssl_protocols",
                "value": "TLSv1.2 TLSv1.3",
            }, {
                "key": "ssl_ciphers",
                "value": "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384",
            }, {
                "key": "ssl_prefer_server_ciphers",
                "value": "off",
            }, {
                "key": "ssl_stapling",
                "value": "on",
            }, {
                "key": "ssl_stapling_verify",
                "value": "on",
            }, {
                "key": "ssl_trusted_certificate",
                "value": "{}/{}/ca.cer".format(ACME_ROOT, cert_name),
            }]

            ws_settings = [{
                "key": "proxy_http_version",
                "value": "1.1",
            }, {
                "key": "proxy_set_header",
                "value": "Upgrade $http_upgrade",
            }, {
                "key": "proxy_set_header",
                "value": 'Connection "Upgrade"',
            }]

            if enable_websocket and websocket_path == "/":
                default_ws_settings = ws_settings
            else:
                default_ws_settings = []

            this_server = {
                "server": server_name,
                "configs": ssl_configs + [{"key": key, "value": custom_settings[key]} for key in custom_settings],
                "locations": [get_default_location("/", local_ip, local_port, extra_configs=default_ws_settings)]
            }

            if enable_compression:
                this_server["configs"].extend(get_gzip_options())

            if enable_websocket and websocket_path != "/":
                this_server["locations"].append(get_default_location(websocket_path, local_ip, local_port, extra_configs=ws_settings))

            servers.append(this_server)  # https
    return servers


if __name__ == "__main__":
    with open("local/config.json") as f:
        configs = json.loads(f.read())

    servers = parse_configs(configs)
    nginx_config = servers_to_nginx(servers)

    with open("local/generated.proxy", "w") as f:
        f.write(nginx_config)
