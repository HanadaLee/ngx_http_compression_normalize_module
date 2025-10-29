
/*
 * Copyright (C) Hanada
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
    ngx_flag_t    enable;
    ngx_array_t  *combinations;
} ngx_http_compression_normalize_conf_t;


typedef struct {
    ngx_str_t     original_accept_encoding;
} ngx_http_compression_normalize_ctx_t;


static ngx_int_t
    ngx_http_compression_normalize_original_accept_encoding_variable(
    ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_compression_normalize_add_variables(ngx_conf_t *cf);

static char *ngx_http_compression_normalize(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static void *ngx_http_compression_normalize_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_compression_normalize_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);

static ngx_int_t ngx_http_compression_normalize_parse_accept_encoding(
    ngx_http_request_t *r, ngx_array_t **encodings);
static ngx_int_t ngx_http_compression_normalize_parse_encoding_part(
    ngx_http_request_t *r, ngx_str_t *part, ngx_array_t *accepted_encodings);
static ngx_int_t ngx_http_compression_normalize_check_combinations(
    ngx_http_request_t *r, ngx_array_t *accepted_encodings,
    ngx_array_t *combinations, ngx_str_t *normalized_accept_encoding);
static ngx_int_t ngx_http_compression_normalize_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_compression_normalize_init(ngx_conf_t *cf);


static ngx_command_t ngx_http_compression_normalize_commands[] = {

    { ngx_string("compression_normalize_accept_encoding"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_compression_normalize,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL
    },

      ngx_null_command
};


static ngx_http_module_t ngx_http_compression_normalize_module_ctx = {
    ngx_http_compression_normalize_add_variables,   /* preconfiguration */
    ngx_http_compression_normalize_init,            /* postconfiguration */

    NULL,                                           /* create main configuration */
    NULL,                                           /* init main configuration */

    NULL,                                           /* create server configuration */
    NULL,                                           /* merge server configuration */

    ngx_http_compression_normalize_create_loc_conf, /* create location config */
    ngx_http_compression_normalize_merge_loc_conf   /* merge location config */
};


ngx_module_t ngx_http_compression_normalize_module = {
    NGX_MODULE_V1,
    &ngx_http_compression_normalize_module_ctx,     /* module context */
    ngx_http_compression_normalize_commands,        /* module directives */
    NGX_HTTP_MODULE,                                /* module type */
    NULL,                                           /* init master */
    NULL,                                           /* init module */
    NULL,                                           /* init process */
    NULL,                                           /* init thread */
    NULL,                                           /* exit thread */
    NULL,                                           /* exit process */
    NULL,                                           /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_http_variable_t  ngx_http_compression_normalize_vars[] = {

    { ngx_string("compression_original_accept_encoding"), NULL,
      ngx_http_compression_normalize_original_accept_encoding_variable,
      0, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_null_string, NULL, NULL, 0, 0, 0 }
};


static ngx_int_t
ngx_http_compression_normalize_original_accept_encoding_variable(
    ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_compression_normalize_ctx_t  *ctx;
    ngx_table_elt_t                    *ae;

    ctx = ngx_http_get_module_ctx(r, ngx_http_compression_normalize_module);

    if (ctx == NULL || ctx->original_accept_encoding.len == 0) {
        ae = r->headers_in.accept_encoding;

        if (ae == NULL || ae->value.len == 0) {
            v->not_found = 1;
            return NGX_OK;
        }

        v->len = ae->value.len;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = ae->value.data;

        return NGX_OK;
    }

    v->len = ctx->original_accept_encoding.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = ctx->original_accept_encoding.data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_compression_normalize_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var, *v;

    for (v = ngx_http_compression_normalize_vars; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}


static void *
ngx_http_compression_normalize_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_compression_normalize_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool,
        sizeof(ngx_http_compression_normalize_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->enable = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_http_compression_normalize_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child)
{
    ngx_http_compression_normalize_conf_t *prev = parent;
    ngx_http_compression_normalize_conf_t *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);

    if (conf->combinations == NULL) {
        conf->combinations = prev->combinations;
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_compression_normalize(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_compression_normalize_conf_t *cncf = conf;

    ngx_str_t        *value;
    ngx_uint_t        i;

    if (cncf->enable != NGX_CONF_UNSET) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (cf->args->nelts == 2 && ngx_strcmp(value[1].data, "off") == 0) {
        cncf->enable = 0;
        return NGX_CONF_OK;
    }

    cncf->enable = 1;

    cncf->combinations = ngx_array_create(cf->pool,
        cf->args->nelts - 1, sizeof(ngx_str_t));
    if (cncf->combinations == NULL) {
        return NGX_CONF_ERROR;
    }

    for (i = 1; i < cf->args->nelts; i++) {
        ngx_str_t *str = ngx_array_push(cncf->combinations);
        if (str == NULL) {
            return NGX_CONF_ERROR;
        }

        *str = value[i];
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_compression_normalize_parse_accept_encoding(ngx_http_request_t *r,
    ngx_array_t **encodings)
{
    ngx_table_elt_t *h;
    ngx_str_t        ae;
    ngx_uint_t       i;
    u_char          *p, *last, *start, *end;
    ngx_str_t       *part;

    h = r->headers_in.accept_encoding;

    if (h == NULL || h->value.len == 0) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
            "normalize_accept_encoding: no accept-encoding header found, "
            "skipping normalization");
        return NGX_DECLINED;
    }

    ae.len = h->value.len;
    ae.data = ngx_pnalloc(r->pool, ae.len);
    if (ae.data == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ngx_memcpy(ae.data, h->value.data, ae.len);

    for (i = 0; i < ae.len; i++) {
        ae.data[i] = ngx_tolower(ae.data[i]);
    }

    while (ae.len > 0 && isspace(ae.data[0])) {
        ae.data++;
        ae.len--;
    }

    while (ae.len > 0 && isspace(ae.data[ae.len - 1])) {
        ae.len--;
    }

    if (ae.len == 0) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "normalize_accept_encoding: accept-encoding header "
                      "is empty after trimming, skipping modification");
        return NGX_DECLINED;
    }

    *encodings = ngx_array_create(r->pool, 4, sizeof(ngx_str_t));
    if (*encodings == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    p = ae.data;
    last = ae.data + ae.len;
    start = p;

    while (p < last) {
        if (*p == ',') {
            end = p;

            while (start < end && isspace(*start)) {
                start++;
            }
            while (end > start && isspace(*(end - 1))) {
                end--;
            }

            if (start < end) {
                part = ngx_array_push(*encodings);
                if (part == NULL) {
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }
                part->len = end - start;
                part->data = start;
            }

            p++;
            start = p;
        } else {
            p++;
        }
    }

    end = p;
    while (start < end && isspace(*start)) {
        start++;
    }

    while (end > start && isspace(*(end - 1))) {
        end--;
    }

    if (start < end) {
        part = ngx_array_push(*encodings);
        if (part == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        part->len = end - start;
        part->data = start;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_compression_normalize_parse_encoding_part(ngx_http_request_t *r,
    ngx_str_t *part, ngx_array_t *accepted_encodings)
{
    u_char     *semicolon;
    ngx_str_t   encoding;
    ngx_str_t   params;
    u_char     *p, *last;
    u_char      c;
    ngx_int_t   q_value_is_zero = 1;  /* default is q=0 */
    ngx_uint_t  decimal_points = 0;

    /* Find ';' */
    semicolon = ngx_strlchr(part->data, part->data + part->len, ';');
    if (semicolon) {
        encoding.data = part->data;
        encoding.len = semicolon - part->data;

        params.data = semicolon + 1;
        params.len = (part->data + part->len) - params.data;
    } else {
        encoding = *part;
        params.data = NULL;
        params.len = 0;
    }

    while (encoding.len > 0 && isspace(encoding.data[0])) {
        encoding.data++;
        encoding.len--;
    }

    while (encoding.len > 0 && isspace(encoding.data[encoding.len - 1])) {
        encoding.len--;
    }

    if (encoding.len == 0) {
        return NGX_OK;
    }

    /* parse q_value */
    if (params.len > 0) {
        p = params.data;
        last = params.data + params.len;

        while (p < last && isspace(*p)) {
            p++;
        }

        /* check 'q=' or 'Q=' */
        if (!(p + 1 < last && (p[0] == 'q' || p[0] == 'Q') && p[1] == '=')) {
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "normalize_accept_encoding: missing 'q=' "
                          "in Accept-Encoding parameters");
            return NGX_OK;
        }

        p += 2;  /* skip 'q=' */

        /* expect is a number */
        if (p >= last || !(p[0] >= '0' && p[0] <= '9')) {
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "normalize_accept_encoding: invalid q-value "
                          "format in Accept-Encoding");
            return NGX_OK;
        }

        while (p < last) {
            c = *p;

            if (c == '.') {
                decimal_points++;
                if (decimal_points > 1) {
                    /* more than one decimal points */
                    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                                  "normalize_accept_encoding: multiple "
                                  "decimal points in q-value");
                    return NGX_OK;
                }

            } else if (c >= '0' && c <= '9') {
                if (c != '0') {
                    q_value_is_zero = 0;  /* non-zero number found */
                }
            } else {
                /* invalid character found */
                ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                              "normalize_accept_encoding: invalid character "
                              "'%c' in q-value", c);
                return NGX_OK;
            }
            p++;
        }

        /* Check if the q value is 0 */
        if (q_value_is_zero) {
            return NGX_OK;
        }
    }

    /* Add to accepted_encodings */
    {
        ngx_str_t *accepted_enc = ngx_array_push(accepted_encodings);
        if (accepted_enc == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        accepted_enc->len = encoding.len;
        accepted_enc->data = ngx_pnalloc(r->pool, encoding.len);
        if (accepted_enc->data == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        ngx_memcpy(accepted_enc->data, encoding.data, encoding.len);
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_compression_normalize_check_combinations(ngx_http_request_t *r,
    ngx_array_t *accepted_encodings, ngx_array_t *combinations,
    ngx_str_t *normalized_accept_encoding)
{
    ngx_uint_t    j, k, i;
    ngx_str_t    *combination, combo, combo_trimmed;
    ngx_uint_t    combinations_nelts;
    ngx_array_t  *combo_parts;
    u_char       *p, *last, *start, *end;
    ngx_str_t    *part;
    ngx_uint_t    all_included, found;
    ngx_str_t    *combo_encodings, combo_encoding;
    ngx_uint_t    combo_encodings_nelts;
    ngx_str_t    *accepted_encs, accepted_encoding;

    combination = combinations->elts;
    combinations_nelts = combinations->nelts;

    for (j = 0; j < combinations_nelts; j++) {
        combo = combination[j];

        if (combo.len == 0) {
            continue;
        }

        combo_trimmed.data = ngx_pnalloc(r->pool, combo.len);
        if (combo_trimmed.data == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        ngx_memcpy(combo_trimmed.data, combo.data, combo.len);
        combo_trimmed.len = combo.len;

        for (i = 0; i < combo_trimmed.len; i++) {
            combo_trimmed.data[i] = ngx_tolower(combo_trimmed.data[i]);
        }

        while (combo_trimmed.len > 0 && isspace(combo_trimmed.data[0])) {
            combo_trimmed.data++;
            combo_trimmed.len--;
        }

        while (combo_trimmed.len > 0 
               && isspace(combo_trimmed.data[combo_trimmed.len - 1]))
        {
            combo_trimmed.len--;
        }

        if (combo_trimmed.len == 0) {
            continue;
        }

        /* split combo */
        combo_parts = ngx_array_create(r->pool, 4, sizeof(ngx_str_t));
        if (combo_parts == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        p = combo_trimmed.data;
        last = combo_trimmed.data + combo_trimmed.len;
        start = p;

        while (p < last) {
            if (*p == ',') {
                end = p;
                while (start < end && isspace(*start)) {
                    start++;
                }

                while (end > start && isspace(*(end - 1))) {
                    end--;
                }

                if (start < end) {
                    part = ngx_array_push(combo_parts);
                    if (part == NULL) {
                        return NGX_HTTP_INTERNAL_SERVER_ERROR;
                    }
                    part->len = end - start;
                    part->data = start;
                }

                p++;
                start = p;
            } else {
                p++;
            }
        }

        /* parse last part */
        end = p;
        while (start < end && isspace(*start)) {
            start++;
        }

        while (end > start && isspace(*(end - 1))) {
            end--;
        }

        if (start < end) {
            part = ngx_array_push(combo_parts);
            if (part == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
            part->len = end - start;
            part->data = start;
        }

        /* Checks if the encodings in the combination are among the accepted encodings */
        all_included = 1;
        combo_encodings = combo_parts->elts;
        combo_encodings_nelts = combo_parts->nelts;
        accepted_encs = accepted_encodings->elts;

        for (k = 0; k < combo_encodings_nelts; k++) {
            combo_encoding = combo_encodings[k];
            found = 0;

            for (i = 0; i < accepted_encodings->nelts; i++) {
                accepted_encoding = accepted_encs[i];

                if (accepted_encoding.len == combo_encoding.len
                    && ngx_strncmp(accepted_encoding.data,
                        combo_encoding.data, accepted_encoding.len) == 0)
                {
                    found = 1;
                    break;
                }
            }

            if (!found) {
                all_included = 0;
                break;
            }
        }

        if (all_included) {
            normalized_accept_encoding->len = combo.len;
            normalized_accept_encoding->data = combo.data;
            return NGX_OK;
        }
    }

    return NGX_DECLINED;
}


static ngx_int_t
ngx_http_compression_normalize_handler(ngx_http_request_t *r)
{
    ngx_http_compression_normalize_conf_t  *cncf;
    ngx_http_compression_normalize_ctx_t   *ctx;
    ngx_table_elt_t                     *h;
    ngx_array_t                         *encoding_parts = NULL;
    ngx_array_t                         *accepted_encodings;
    ngx_str_t                            normalized_accept_encoding;
    ngx_uint_t                           i;
    ngx_str_t                           *enc_parts;

    cncf = ngx_http_get_module_loc_conf(r,
        ngx_http_compression_normalize_module);

    if (!cncf->enable) {
        return NGX_DECLINED;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_compression_normalize_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(r->pool,
            sizeof(ngx_http_compression_normalize_ctx_t));
        if (ctx == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        ngx_http_set_ctx(r, ctx, ngx_http_compression_normalize_module);
    }

    h = r->headers_in.accept_encoding;

    if (h == NULL) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "normalize_accept_encoding: no accept-encoding header "
                      "found, skipping normalization");
        return NGX_DECLINED;
    }

    /* Save original Accept-Encoding request header */
    ctx->original_accept_encoding.len = h->value.len;
    ctx->original_accept_encoding.data = ngx_pnalloc(r->pool, h->value.len);
    if (ctx->original_accept_encoding.data == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_memcpy(ctx->original_accept_encoding.data,
        h->value.data, h->value.len);

    /* parse Accept-Encoding request header */
    if (ngx_http_compression_normalize_parse_accept_encoding(r,
            &encoding_parts) != NGX_OK)
    {
        return NGX_DECLINED;
    }

    /* parse compress encoding and q value */
    accepted_encodings = ngx_array_create(r->pool,
        encoding_parts->nelts, sizeof(ngx_str_t));
    if (accepted_encodings == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    enc_parts = encoding_parts->elts;
    for (i = 0; i < encoding_parts->nelts; i++) {
        if (ngx_http_compression_normalize_parse_encoding_part(r,
            &enc_parts[i], accepted_encodings) != NGX_OK)
        {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    normalized_accept_encoding.len = 0;
    normalized_accept_encoding.data = NULL;
    if (ngx_http_compression_normalize_check_combinations(r,
        accepted_encodings, cncf->combinations,
        &normalized_accept_encoding) == NGX_OK)
    {
        h->value.len = normalized_accept_encoding.len;
        h->value.data = normalized_accept_encoding.data;
    }

    return NGX_DECLINED;
}


static ngx_int_t
ngx_http_compression_normalize_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_PRECONTENT_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_compression_normalize_handler;

    return NGX_OK;
}