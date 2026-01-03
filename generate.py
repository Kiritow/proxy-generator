import os
import time
import yaml
import argparse
import subprocess
from typing import TypedDict
from pydantic import BaseModel


def list_acme_domains():
    ACME_BIN = "/home/{}/.acme.sh/acme.sh".format(os.getenv("USER"))
    domains: dict[str, str] = {}

    output = subprocess.check_output([ACME_BIN, "--list", "--listraw"], encoding="utf-8").splitlines()[1:]
    for line in output:
        parts = line.split('|')
        domain = parts[0].strip()
        output2 = subprocess.check_output([ACME_BIN, "--info", "-d", domain], encoding="utf-8")
        for info_line in output2.splitlines():
            if info_line.startswith("DOMAIN_CONF="):
                conf_path = info_line.split('=')[1].strip()
                conf_dir = os.path.dirname(conf_path)
                domains[domain] = conf_dir
                break
        else:
            raise Exception(f"Could not find DOMAIN_CONF for domain {domain}")

    return domains


class TLocation(TypedDict):
    path: str
    options: list[tuple[str, str]]


class TServer(TypedDict):
    server_name: str
    listen_port: int
    listen_ssl: bool
    server_options: list[tuple[str, str]]
    locations: list[TLocation]


def get_proxy_location(path: str, local_addr: str, local_port: int):
    options: list[tuple[str, str]] = []
    options.append(("add_header", "X-Served-By $host"))
    options.append(("proxy_set_header", "Host $host"))
    options.append(("proxy_set_header", "X-Forwarded-Scheme $scheme"))
    options.append(("proxy_set_header", "X-Forwarded-Proto $scheme"))
    options.append(("proxy_set_header", "X-Forwarded-For $remote_addr"))
    options.append(("proxy_set_header", "X-Real-IP $remote_addr"))
    options.append(("proxy_set_header", "X-Real-Port $remote_port"))
    options.append(("proxy_pass", "http://{}:{}".format(local_addr, local_port)))
    
    conf: TLocation = {
        "path": "^~ {}".format(path),
        "options": options,
    }
    return conf


def get_gzip_options():
    options: list[tuple[str, str]] = []
    options.append(("gzip", "on"))
    options.append(("gzip_disable", "msie6"))
    options.append(("gzip_vary", "on"))
    options.append(("gzip_proxied", "any"))
    options.append(("gzip_comp_level", "6"))
    options.append(("gzip_buffers", "4 16k"))
    options.append(("gzip_http_version", "1.1"))
    options.append(("gzip_types", "application/atom+xml application/javascript application/x-javascript application/json application/rss+xml application/vnd.ms-fontobject application/x-font application/x-font-opentype application/x-font-otf application/x-font-truetype application/x-font-ttf application/x-web-app-manifest+json application/xhtml+xml application/xml font/opentype font/otf font/ttf image/svg+xml image/x-icon text/css text/plain text/javascript text/x-component text/xml"))

    return options


def get_ssl_options(fullchain_path: str, cert_key_path: str, ca_path: str):
    options: list[tuple[str, str]] = []
    options.append(("ssl_certificate", '"{}"'.format(fullchain_path)))
    options.append(("ssl_certificate_key", '"{}"'.format(cert_key_path)))
    options.append(("ssl_trusted_certificate", '"{}"'.format(ca_path)))
    options.append(("ssl_session_timeout", "1d"))
    options.append(("ssl_session_cache", "shared:MozSSL:10m"))
    options.append(("ssl_session_tickets", "off"))
    options.append(("ssl_protocols", "TLSv1.2 TLSv1.3"))
    options.append(("ssl_ciphers", "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384"))
    options.append(("ssl_prefer_server_ciphers", "off"))
    options.append(("ssl_stapling", "on"))
    options.append(("ssl_stapling_verify", "on"))

    return options


def get_disable_cache_options():
    options: list[tuple[str, str]] = []
    options.append(("proxy_cache_bypass", "1"))
    options.append(("proxy_no_cache", "1"))
    options.append(("add_header", "Last-Modified $date_gmt"))
    options.append(("add_header", 'Cache-Control "no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0"'))
    options.append(("if_modified_since", "off"))
    options.append(("expires", "off"))
    options.append(("etag", "off"))

    return options


def get_realtime_options():
    options: list[tuple[str, str]] = []
    options.append(("proxy_buffering", "off"))
    options.append(("proxy_ignore_client_abort", "on"))
    options.append(("proxy_socket_keepalive", "on"))

    return options


def get_websocket_options():
    options: list[tuple[str, str]] = []
    options.append(("proxy_http_version", "1.1"))
    options.append(("proxy_set_header", "Upgrade $http_upgrade"))
    options.append(("proxy_set_header", 'Connection $connection_upgrade'))

    return options


class ConfigKeyItemModel(BaseModel):
    key: str
    value: str


class ConfigLocationModel(BaseModel):
    enable: bool | None = None # default to true
    path: str
    ip: str | None = None # default to 127.0.0.1
    port: int
    websocket: bool | None = None # default to false
    disable_cache: bool | None = None # default to false
    realtime: bool | None = None # default to false
    options: list[ConfigKeyItemModel] | None = None


class ConfigItemModel(BaseModel):
    enable: bool | None = None # default to true
    listen_port: int | None = None # default to 80 for http, 443 for https
    server_name: str
    cert_name: str | None = None # if specified, enable https by default
    https: bool | None = None # default to false, unless cert is specified
    gzip: bool | None = None # default to false
    options: list[ConfigKeyItemModel] | None = None

    default: ConfigLocationModel
    locations: list[ConfigLocationModel] | None = None


class ConfigModel(BaseModel):
    servers: list[ConfigItemModel]


def parse_configs(configs: list[ConfigItemModel], copy_cert_dir: str | None, cert_path: str | None):
    servers: list[TServer] = []
    acme_domains = list_acme_domains()
    to_copy_files: list[tuple[str, str]] = []
    
    def add_cert_file(srcpath: str):
        if copy_cert_dir is None:
            assert srcpath.startswith("/"), "Source path must be absolute."
            return srcpath

        dest_filename = os.path.join(copy_cert_dir, "{}{}".format(len(to_copy_files), os.path.splitext(srcpath)[1]))
        use_filename = os.path.join(cert_path, "{}{}".format(len(to_copy_files), os.path.splitext(srcpath)[1])) if cert_path is not None else dest_filename
        to_copy_files.append((srcpath, dest_filename))

        assert use_filename.startswith("/"), "Destination path must be absolute."
        return use_filename

    for config in configs:
        if config.enable is not None and not config.enable:
            continue
        
        current_http_server: TServer = {
            "server_name": config.server_name,
            "listen_port": config.listen_port or 80,
            "listen_ssl": False,
            "locations": [],
            "server_options": []
        }
        current_https_server: TServer = {
            "server_name": config.server_name,
            "listen_port": config.listen_port or 443,
            "listen_ssl": True,
            "locations": [],
            "server_options": []
        }
        
        if config.https:
            cert_name = config.cert_name or config.server_name
            if cert_name not in acme_domains:
                raise Exception("Certificate for {} not found in acme domains.".format(cert_name))
            
            cert_key_path = add_cert_file(os.path.join(acme_domains[cert_name], "{}.key".format(cert_name)))
            fullchain_path = add_cert_file(os.path.join(acme_domains[cert_name], "fullchain.cer"))
            ca_path = add_cert_file(os.path.join(acme_domains[cert_name], "ca.cer"))

            ssl_options = get_ssl_options(fullchain_path, cert_key_path, ca_path)
            current_https_server["server_options"].extend(ssl_options)

        if config.gzip:
            current_http_server["server_options"].extend(get_gzip_options())
            current_https_server["server_options"].extend(get_gzip_options())
            
        if config.default.enable is None or config.default.enable:
            default_location = get_proxy_location(config.default.path or "/", config.default.ip or "127.0.0.1", config.default.port)
            if config.default.disable_cache:
                default_location["options"].extend(get_disable_cache_options())
            if config.default.realtime:
                default_location["options"].extend(get_realtime_options())
            if config.default.websocket:
                default_location["options"].extend(get_websocket_options())
            if config.default.options:
                for option in config.default.options:
                    default_location["options"].append((option.key, option.value))

            current_http_server["locations"].append(default_location)
            current_https_server["locations"].append(default_location)

        for config_location in config.locations or []:
            if config_location.enable is not None and not config_location.enable:
                continue
            
            location = get_proxy_location(config_location.path, config_location.ip or config.default.ip or "127.0.0.1", config_location.port or config.default.port)
            if config_location.disable_cache:
                location["options"].extend(get_disable_cache_options())
            if config_location.realtime:
                location["options"].extend(get_realtime_options())
            if config_location.websocket:
                location["options"].extend(get_websocket_options())
            if config_location.options:
                for option in config_location.options:
                    location["options"].append((option.key, option.value))

            current_http_server["locations"].append(location)
            current_https_server["locations"].append(location)
        
        if config.https:
            current_http_server["server_options"] = [("return", "301 https://$host$request_uri")]
            current_http_server["locations"] = []
            servers.append(current_http_server)
            servers.append(current_https_server)
        else:
            servers.append(current_http_server)

    return servers, to_copy_files


def simple_format(lines: list[str], indent: int = 2):
    output: list[str] = []
    level = 0

    for line in lines:
        sline = line.strip()
        if sline.startswith('#'):
            output.append(sline)
            continue
        if sline.startswith('}'):
            level = max(0, level - 1)
        output.append(' ' * indent * level + sline)
        if sline.endswith('{'):
            level += 1

    return output


def render_nginx_conf(servers: list[TServer]):
    output = ["# Auto generated at {}".format(time.strftime("%Y-%m-%d %H:%M:%S"))]
    output.extend([
        "map $http_upgrade $connection_upgrade {",
        "default upgrade;",
        '"" close;',
        "}",
    ])
    for server in servers:
        output.append("server {")
        if server["listen_ssl"]:
            output.append("listen {} ssl;".format(server["listen_port"]))
        else:
            output.append("listen {};".format(server["listen_port"]))
        output.append("server_name {};".format(server["server_name"]))
        
        for item in server["server_options"]:
            output.append("{} {};".format(item[0], item[1]))
            
        for location in server["locations"]:
            output.append("location {} {{".format(location["path"]))
            for item in location["options"]:
                output.append("{} {};".format(item[0], item[1]))
            output.append("}")
        
        output.append("}")

    return '\n'.join(simple_format(output))


if __name__ == "__main__":
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument("--config", help="Path to the YAML configuration file", type=str)
    arg_parser.add_argument("--output", help="Output filename for the generated Nginx configuration", type=str)
    arg_parser.add_argument("--copy-cert", help="Copy certificates from acme.sh to specified directory (useful for dockerized nginx)", type=str)

    args = arg_parser.parse_args()
    config_path: str | None = args.config
    if config_path is None:
        config_path = "config.yaml"
        if not os.path.isfile(config_path):
            config_path = "config.yml"
        if not os.path.isfile(config_path):
            raise Exception("No configuration file specified and default config.yaml or config.yml not found.")
    elif not os.path.isfile(config_path):
        raise Exception("Configuration file {} not found.".format(config_path))
    output_filepath: str = args.output or "proxy.conf"
    copy_cert_dir: str | None = args.copy_cert
    
    if copy_cert_dir is not None:
        host_path, container_path = copy_cert_dir.split(':')
    else:
        host_path = container_path = None

    with open(config_path, "r") as f:
        raw_config = yaml.safe_load(f)
        config = ConfigModel.model_validate(raw_config)

    servers, to_copy_files = parse_configs(config.servers, host_path, container_path)
    print("Parsed {} server configurations. {} files to copy.".format(len(servers), len(to_copy_files)))

    nginx_config = render_nginx_conf(servers)

    print("Writing generated Nginx configuration to {}...".format(output_filepath))
    with open(output_filepath, "w") as f:
        f.write(nginx_config)
    
    print("Copying {} certificate files...".format(len(to_copy_files)))
    for srcpath, destpath in to_copy_files:
        print("COPY {} -> {}".format(srcpath, destpath))
        subprocess.check_call(["cp", srcpath, destpath])
