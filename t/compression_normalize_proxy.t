#!/usr/bin/perl

# Tests for normalized request headers forwarded to an upstream.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http rewrite proxy/);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen 127.0.0.1:8080;
        server_name localhost;

        compression_normalize_accept_encoding gzip,br gzip;
        add_header X-Normalized $http_accept_encoding always;
        add_header X-Original $compression_original_accept_encoding always;

        location /buffered/ {
            proxy_pass http://127.0.0.1:8081/;
        }

        location /unbuffered/ {
            proxy_buffering off;
            proxy_pass http://127.0.0.1:8081/;
        }

        location /off/ {
            compression_normalize_accept_encoding off;
            proxy_pass http://127.0.0.1:8081/;
        }
    }

    server {
        listen 127.0.0.1:8081;
        add_header X-Upstream-Encoding $http_accept_encoding always;
        add_header X-Upstream-Kept $http_x_kept always;
        return 200 upstream;
    }
}

EOF

$t->run();

###############################################################################

for my $prefix ('buffered', 'unbuffered') {
    my $response = request($prefix, 'BR, gzip;q=0.1');
    like($response, qr/^X-Upstream-Encoding: gzip,br\x0d$/m,
        "$prefix forwards normalized value");
    like($response, qr/^X-Original: BR, gzip;q=0.1\x0d$/m,
        "$prefix preserves original value");

    for my $accept ('deflate', 'gzip;q=0') {
        $response = request($prefix, $accept);
        like($response, qr/^HTTP\/1.1 200 /, "$prefix $accept status");
        unlike($response, qr/^X-Upstream-Encoding:/m,
            "$prefix does not forward removed $accept");
        unlike($response, qr/^X-Normalized:/m,
            "$prefix removed $accept is absent locally");
        like($response, qr/^X-Original: \Q$accept\E\x0d$/m,
            "$prefix removed $accept remains available as original");
    }

    $response = request($prefix, 'deflate',
        "Accept-Encoding: deflate\r\nX-Kept: retained\r\n");
    unlike($response, qr/^X-Upstream-Encoding:/m,
        "$prefix removes all repeated fields");
    like($response, qr/^X-Upstream-Kept: retained\x0d$/m,
        "$prefix preserves other fields");
}

for my $position (0, 1, 10, 19, 20, 21, 39, 40, 42) {
    my @headers = ('Host: localhost', 'X-Kept: retained',
        map { "X-Padding-$_: padding" } 1 .. 40);
    splice @headers, $position, 0, 'Accept-Encoding: deflate';
    my $response = http("GET /buffered/ HTTP/1.0\r\n"
        . join("\r\n", @headers) . "\r\n\r\n");

    like($response, qr/^HTTP\/1.1 200 /, "removal at position $position");
    unlike($response, qr/^X-Upstream-Encoding:/m,
        "removed field is not forwarded at position $position");
    like($response, qr/^X-Upstream-Kept: retained\x0d$/m,
        "other fields survive removal at position $position");
}

my $response = http("GET /buffered/ HTTP/1.0\r\n"
    . "Accept-Encoding: deflate\r\n\r\n");
like($response, qr/^HTTP\/1.1 200 /, 'removing the only request header');
unlike($response, qr/^X-Upstream-Encoding:/m,
    'the only header is not forwarded');

$response = request('off', 'deflate');
like($response, qr/^X-Upstream-Encoding: deflate\x0d$/m,
    'off preserves the forwarded value');

$t->stop();
unlike($t->read_file('error.log'), qr/\[(?:alert|emerg)\]|Sanitizer|runtime error:/,
    'no header removal lifecycle errors');
undef $t;

done_testing();

###############################################################################

sub request {
    my ($prefix, $accept, $extra) = @_;
    $extra //= '';

    return http("GET /$prefix/ HTTP/1.0\r\nHost: localhost\r\n"
        . "Accept-Encoding: $accept\r\n$extra\r\n");
}

###############################################################################
