#!/usr/bin/perl

# Tests for ngx_http_compression_normalize_module.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http rewrite ngx_expr_module/)->plan(13);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        expr br_profile str_eq $arg_profile br;

        when br_profile {
            compression_normalize_accept_encoding br;
        }

        compression_normalize_accept_encoding gzip,br gzip;

        location / {
            root %%TESTDIR%%;
            add_header X-Normalized $http_accept_encoding always;
            add_header X-Original
                       $compression_original_accept_encoding always;
        }

        location = /off {
            compression_normalize_accept_encoding off;
            alias %%TESTDIR%%/index.html;
            add_header X-Normalized $http_accept_encoding always;
            add_header X-Original
                       $compression_original_accept_encoding always;
        }
    }
}

EOF

$t->write_file('index.html', 'normalized');
$t->run();

###############################################################################

my $response = request('/', 'BR, GZip');
like($response, qr/^X-Normalized: gzip,br\x0d$/m,
	'preferred combination normalizes case and order');
like($response, qr/^X-Original: BR, GZip\x0d$/m,
	'original variable preserves request value');

$response = request('/?profile=br', 'gzip, br');
like($response, qr/^X-Normalized: br\x0d$/m,
	'matching condition selects its combination');
like($response, qr/^X-Original: gzip, br\x0d$/m,
	'conditional normalization preserves original value');

$response = request('/?profile=other', 'br, gzip');
like($response, qr/^X-Normalized: gzip,br\x0d$/m,
	'condition miss uses ordered fallback');

$response = request('/', 'gzip;q=0, br;q=1');
unlike($response, qr/^X-Normalized:/m,
	'q=0 removes encoding and unmatched header is deleted');
like($response, qr/^X-Original: gzip;q=0, br;q=1\x0d$/m,
	'q-value input remains available as original');

$response = request('/', 'deflate');
unlike($response, qr/^X-Normalized:/m,
	'unsupported encoding removes accept-encoding header');
like($response, qr/^X-Original: deflate\x0d$/m,
	'unsupported encoding remains available as original');

$response = http_get('/');
unlike($response, qr/^X-Normalized:/m,
	'missing header stays absent');
unlike($response, qr/^X-Original:/m,
	'missing header has no original value');

$response = request('/off', 'br, gzip');
like($response, qr/^X-Normalized: br, gzip\x0d$/m,
	'off leaves request header unchanged');
like($response, qr/^X-Original: br, gzip\x0d$/m,
	'off exposes unchanged header as original');

###############################################################################

sub request {
	my ($uri, $accept_encoding) = @_;

	return http(<<EOF);
GET $uri HTTP/1.1
Host: localhost
Accept-Encoding: $accept_encoding
Connection: close

EOF
}

###############################################################################
