# ngx_http_compression_normalize_module

# Describe

`ngx_http_compression_normalize_module` is an Nginx module designed to parse, normalize, and manage the Accept-Encoding headers from client requests. It ensures consistent handling of compression algorithms by standardizing the Accept-Encoding values, facilitating better compression management and improved vary cache performance.

# Table of Content

- [ngx\_http\_compression\_normalize\_module](#ngx_http_compression_normalize_module)
- [Describe](#describe)
- [Table of Content](#table-of-content)
- [Status](#status)
- [Synopsis](#synopsis)
- [Installation](#installation)
- [Directives](#directives)
	- [compression\_normalize\_accept\_encoding](#compression_normalize_accept_encoding)
- [Variables](#variables)
	- [$compression\_original\_accept\_encoding](#compression_original_accept_encoding)
- [Author](#author)
- [License](#license)

# Status

This Nginx module is currently considered experimental. Issues and PRs are welcome if you encounter any problems.

# Synopsis

```nginx
http {
    compression_normalize_accept_encoding gzip,br,zstd gzip,br zstd br gzip;

    server {
        listen 80;
        server_name example.com;

        location / {
            # Your configurations
        }
    }
}
```

# Installation

To use theses modules, configure your nginx branch with `--add-module=/path/to/ngx_http_compression_normalize_module`.

# Directives

## compression_normalize_accept_encoding

**Syntax:** *compression_normalize_accept_encoding combinations1 \[combinations2 ..\] | off;*

**Default:** *compression_normalize_accept_encoding off;*

**Context:** *http, server, location*

Enables the normalization of the Accept-Encoding header by specifying preferred combinations of compression algorithms. This directive accepts a list of compression methods, allowing to define the order and priority of encoding types that the server should prefer when responding to client requests.

For example, with the following configuration

```nginx
compression_normalize_accept_encoding gzip,br,zstd gzip,br zstd br gzip;
```

If the request header Accept-Encoding contains gzip, br and zstd at the same time, the value of the standardized Accept-Encoding header is `gzip,br,zstd`. If the above conditions are not met, but the request header contains gzip and br, the value of the standardized Accept-Encoding header is `gzip,br`. And so on, until all the combinations given by the `compression_normalize_accept_encoding` directive are checked. If no combination is hit at this time, the Accept-Encoding header is directly deleted.

A value of `off` will disable this feature.

# Variables

## \$compression_original_accept_encoding

keeps the original value of request Accept-Encoding header.

# Author

Hanada im@hanada.info

# License

This Nginx module is licensed under [BSD 2-Clause License](LICENSE).
