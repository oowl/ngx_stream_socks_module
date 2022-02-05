#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>

#define NGX_STREAM_SOCKS_VERSION                 0x05
#define NGX_STREAM_SOCKS_RESERVED                0x00
#define NGX_STREAM_SOCKS_CMD_CONNECT             0x01
#define NGX_STREAM_SOCKS_ADDR_IPv4               0x01
#define NGX_STREAM_SOCKS_ADDR_IPv6               0x04
#define NGX_STREAM_SOCKS_ADDR_DOMAIN_NAME        0x03

#define NGX_STREAM_SOCKS_AUTH_NO_AUTHENTICATION 0x00
#define NGX_STREAM_SOCKS_AUTH_GSSAPI            0x01
#define NGX_STREAM_SOCKS_AUTH_USER_PASSWORD     0x02
#define NGX_STREAM_SOCKS_AUTH_IANA              0x03
#define NGX_STREAM_SOCKS_AUTH_PRIVATE           0x80
#define NGX_STREAM_SOCKS_AUTH_NO_METHODS        0xff

#define NGX_STREAM_SOCKS_CMD_CONNECT            0x01
#define NGX_STREAM_SOCKS_CMD_BIND               0x02
#define NGX_STREAM_SOCKS_CMD_UDP                0x03

#define NGX_STREAM_SOCKS_ATYPE_IPV4             0x01
#define NGX_STREAM_SOCKS_ATYPE_HOST             0x03
#define NGX_STREAM_SOCKS_ATYPE_IPV6             0x04

#define NGX_STREAM_SOCKS_BUFFER_SIZE            128


#if defined(nginx_version) && nginx_version >= 1005008
#define __ngx_sock_ntop ngx_sock_ntop
#else
#define __ngx_sock_ntop(sa, slen, p, len, port) ngx_sock_ntop(sa, p, len, port)
#endif

#define ngx_stream_socks_parse_uint16(p)  ((p)[0] << 8 | (p)[1])

typedef struct {
    ngx_stream_complex_value_t   text;
    ngx_str_t                       name;
    ngx_str_t                       passwd;
} ngx_stream_socks_srv_conf_t;


typedef struct {
    enum {
        sock_preauth = 0,
        socks_auth,
        socks_connect,
        socks_connecting,
        socks_done
    } state;
    ngx_uint_t  auth;
    ngx_str_t   name;
    ngx_str_t   passwd;
    ngx_buf_t   *buf;
    ngx_uint_t  cmd;
    ngx_uint_t  atype;
    ngx_str_t   dst_addr;
    in_port_t   dst_port;
    ngx_chain_t *out;
} ngx_stream_socks_ctx_t;


static void ngx_stream_socks_handler(ngx_stream_session_t *s);
static void ngx_stream_socks_write_handler(ngx_event_t *ev);
static void ngx_stream_socks_read_handler(ngx_event_t *ev);

static void *ngx_stream_socks_create_srv_conf(ngx_conf_t *cf);
static char *ngx_stream_socks(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_stream_socks_user_passwd(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


static ngx_command_t  ngx_stream_socks_commands[] = {

    { ngx_string("socks"),
      NGX_STREAM_SRV_CONF|NGX_CONF_NOARGS,
      ngx_stream_socks,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("socks_user_passwd"),
      NGX_STREAM_SRV_CONF|NGX_CONF_TAKE2,
      ngx_stream_socks_user_passwd,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_stream_module_t  ngx_stream_socks_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    ngx_stream_socks_create_srv_conf,     /* create server configuration */
    NULL                                   /* merge server configuration */
};


ngx_module_t  ngx_stream_socks_module = {
    NGX_MODULE_V1,
    &ngx_stream_socks_module_ctx,         /* module context */
    ngx_stream_socks_commands,            /* module directives */
    NGX_STREAM_MODULE,                     /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static void
ngx_stream_socks_handler(ngx_stream_session_t *s)
{
    ngx_str_t                      text;
    ngx_buf_t                     *b;
    ngx_connection_t              *c;
    ngx_stream_socks_ctx_t       *ctx;
    ngx_stream_socks_srv_conf_t  *rscf;

    c = s->connection;

    c->log->action = "socksing";

    ctx = ngx_pcalloc(c->pool, sizeof(ngx_stream_socks_ctx_t));
    if (ctx == NULL) {
        ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return NGX_ERROR;
    }

    ctx->buf = ngx_create_temp_buf(c->pool, NGX_STREAM_SOCKS_BUFFER_SIZE);

    if (ctx->buf == NULL) {
        return NGX_ERROR;
    }

    ngx_stream_set_ctx(s, ctx, ngx_stream_socks_module);

    c->write->handler = ngx_stream_socks_write_handler;
    c->read->handler = ngx_stream_socks_read_handler;

    return NGX_DONE;
}


static void
ngx_stream_socks_write_handler(ngx_event_t *ev)
{
    ngx_connection_t         *c;
    ngx_stream_session_t     *s;
    ngx_stream_socks_ctx_t  *ctx;

    c = ev->data;
    s = c->data;

    if (ev->timedout) {
        ngx_connection_error(c, NGX_ETIMEDOUT, "connection timed out");
        ngx_stream_finalize_session(s, NGX_STREAM_OK);
        return;
    }

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_socks_module);

    if (ngx_stream_top_filter(s, ctx->out, 1) == NGX_ERROR) {
        ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    ctx->out = NULL;

    if (!c->buffered) {
        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0,
                       "stream socks done sending");
        ngx_stream_finalize_session(s, NGX_STREAM_OK);
        return;
    }

    if (ngx_handle_write_event(ev, 0) != NGX_OK) {
        ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    ngx_add_timer(ev, 5000);
}

static void
ngx_stream_socks_read_handler(ngx_event_t *ev)
{
    size_t                   size;
    ssize_t                  n;
    ngx_connection_t         *c;
    ngx_stream_session_t     *s;
    ngx_stream_socks_ctx_t   *ctx;
    ngx_stream_socks_srv_conf_t *sscf;
    u_char                   *buf;
    u_char                   out_buf[128];
    ngx_sockaddr_t              dst_sockaddr;


    ngx_uint_t               len;

    c = ev->data;
    s = c->data;

    if (ev->timedout) {
        ngx_connection_error(c, NGX_ETIMEDOUT, "connection timed out");
        ngx_stream_finalize_session(s, NGX_STREAM_OK);
        return;
    }

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_socks_module);

    sscf = ngx_stream_get_module_srv_conf(s, ngx_stream_socks_module);

    if (ctx->state <= socks_connect && ctx->buf) {
        size = ctx->buf->end - ctx->buf->last;

        if (size == 0) {
            ngx_log_error(NGX_LOG_ERR, c->log, 0, "socks buffer full");
            ngx_stream_finalize_session(s, NGX_STREAM_BAD_REQUEST);
            return;
        }

        n = ngx_recv(c, ctx->buf->last, size);
        if (n == NGX_ERROR || n == 0) {
            ngx_stream_finalize_session(s, NGX_STREAM_BAD_REQUEST);
            return;
        }

        if (n == NGX_AGAIN) {
            return;
        }

        ctx->buf->last += n;
    }

    if (ctx->buf->last - ctx->buf->pos == 0) {
        ngx_stream_finalize_session(s, NGX_STREAM_BAD_REQUEST);
        return;
    } 
    size = ctx->buf->last - ctx->buf->pos;

    out_buf[0] = NGX_STREAM_SOCKS_VERSION;

    switch (ctx->state)
    {
    case sock_preauth:
        if (size < 2) {
            return;
        }
        buf = ctx->buf->pos;
        if (buf[0] != NGX_STREAM_SOCKS_VERSION && buf[1] == 0) {
            ngx_stream_finalize_session(s, NGX_STREAM_BAD_REQUEST);
            return;
        }
        // method count
        len = buf[1];
        if (size < 2 + len) {
            return;
        }

        ngx_copy(ctx->buf->pos, ctx->buf->pos + 2 + len, size - len -2);
        ctx->buf->last = ctx->buf->last - len - 2;

        for (int i = 0; i < len; i++) {
            if (buf[2+i] == NGX_STREAM_SOCKS_AUTH_USER_PASSWORD) {
                out_buf[1] = NGX_STREAM_SOCKS_AUTH_USER_PASSWORD;
                ctx->auth = NGX_STREAM_SOCKS_AUTH_USER_PASSWORD;
                ctx->state = socks_auth;
                break;
            }

            if (buf[2+i] == NGX_STREAM_SOCKS_AUTH_NO_AUTHENTICATION) {
                out_buf[1] = NGX_STREAM_SOCKS_AUTH_NO_AUTHENTICATION;
                ctx->auth = NGX_STREAM_SOCKS_AUTH_NO_AUTHENTICATION;
                ctx->state = socks_connect;
                break;
            }
        }

        // ensure send
        if (ngx_send(c, out_buf, 2) != 2) {
            ngx_stream_finalize_session(s, NGX_STREAM_BAD_REQUEST);
            return;
        }
        break;

    case socks_auth:
        if (size < 2) {
            return;
        }
        buf = ctx->buf->pos;
        if (buf[0] != NGX_STREAM_SOCKS_VERSION && buf[1] == 0) {
            ngx_stream_finalize_session(s, NGX_STREAM_BAD_REQUEST);
            return;
        }
        // method count
        len = buf[1];
        if (size < 2 + len + 1) {
            return;
        }

        if (size < 2 + len + 1 + buf[2+len]) {
            return;
        }

        ctx->name.data = ngx_pcalloc(c->pool, len);
        ctx->name.len = len;
        ngx_memcpy(ctx->name.data, buf + 2, len);

        len = buf[2+len];
        buf = buf + 2 + n;

        ctx->passwd.data = ngx_pcalloc(c->pool, len);
        ctx->passwd.len = len;
        ngx_memcpy(ctx->passwd.data, buf + 1, len);

        len = 3 + ctx->passwd.len + ctx->name.len;
        ngx_copy(ctx->buf->pos, ctx->buf->pos + len, size - len);
        ctx->buf->last = ctx->buf->last - len - 2;

        if (sscf->name.len != 0 && sscf->passwd.len != 0) {
            if (sscf->name.len != ctx->name.len || sscf->passwd.len != ctx->passwd.len ||
                    ngx_strncmp(sscf->name.data, ctx->name.data, sscf->name.len) != 0 ||
                    ngx_strncmp(sscf->passwd.data, ctx->passwd.data, sscf->passwd.len) != 0) {
                out_buf[1] = 0x01;
                if (ngx_send(c, out_buf, 2) != 2) {
                    ngx_stream_finalize_session(s, NGX_STREAM_BAD_REQUEST);
                    return;
                }
                ngx_stream_finalize_session(s, NGX_STREAM_FORBIDDEN);
                return;
            }
        }

        out_buf[1] = 0x00;
        if (ngx_send(c, out_buf, 2) != 2) {
            ngx_stream_finalize_session(s, NGX_STREAM_BAD_REQUEST);
            return;
        }

        ctx->state = socks_connect; 
        break;
    
    case socks_connect:
        if (size < 6) {
            return;
        }
        buf = ctx->buf->pos;
        if (buf[0] != NGX_STREAM_SOCKS_VERSION) {
            ngx_stream_finalize_session(s, NGX_STREAM_BAD_REQUEST);
            return;
        }

        ctx->cmd = buf[1];
        ctx->atype = buf[3];
        switch (ctx->atype)
        {
        case NGX_STREAM_SOCKS_ATYPE_IPV4:
            len = 4;
            if (size < 5 + len) {
                return;
            }
            dst_sockaddr.sockaddr_in.sin_family = AF_INET;
            dst_sockaddr.sockaddr_in.sin_port = 0;
            ngx_memcpy(&dst_sockaddr.sockaddr_in.sin_addr, buf[4], 4);
            ctx->dst_addr.data = ngx_pcalloc(c->pool, NGX_INET_ADDRSTRLEN);
            ctx->dst_addr.len = ngx_sock_ntop(&dst_sockaddr.sockaddr, sizeof(struct sockaddr_in), ctx->dst_addr.data,
                        NGX_INET_ADDRSTRLEN, 0);
            break;
        case NGX_STREAM_SOCKS_ATYPE_HOST:
            len = buf[4] + 1;
            if (size < 5 + len) {
                return;
            }
            ctx->dst_addr.data = ngx_pcalloc(c->pool, len - 1);
            ctx->dst_addr.len = len - 1;
            ngx_memcpy(ctx->dst_addr.data, buf[5], len - 1);
            break;
        case NGX_STREAM_SOCKS_ATYPE_IPV6:
            len = 16;
            if (size < 5 + len) {
                return;
            }
            dst_sockaddr.sockaddr_in6.sin6_family = AF_INET6;
            dst_sockaddr.sockaddr_in6.sin6_port = 0;
            ngx_memcpy(&dst_sockaddr.sockaddr_in6.sin6_addr, buf[4], 16);
            ctx->dst_addr.data = ngx_pcalloc(c->pool, NGX_INET6_ADDRSTRLEN);
            ctx->dst_addr.len = ngx_sock_ntop(&dst_sockaddr.sockaddr, sizeof(struct sockaddr_in6), ctx->dst_addr.data,
                        NGX_INET6_ADDRSTRLEN, 0);
            break;
        default:
            ngx_stream_finalize_session(s, NGX_STREAM_BAD_REQUEST);
            return;
        }

        ctx->dst_port = ngx_stream_socks_parse_uint16(buf+4+len);
        out_buf[1] = 0x00;
        out_buf[2] = 0x00;
        out_buf[3] = ctx->atype;
        out_buf[4] = 0x00;
        out_buf[5] = 0x00;
        out_buf[6] = 0x00;
        if (ngx_send(c, out_buf, 6) != 6) {
            ngx_stream_finalize_session(s, NGX_STREAM_BAD_REQUEST);
            return;
        }
        ctx->state = socks_connecting;
        break;
    default:
        break;
    }

    return;
}


static void *
ngx_stream_socks_create_srv_conf(ngx_conf_t *cf)
{
    ngx_stream_socks_srv_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_stream_socks_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }
    return conf;
}


static char *
ngx_stream_socks(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_core_srv_conf_t          *cscf;

    cscf = ngx_stream_conf_get_module_srv_conf(cf, ngx_stream_core_module);

    cscf->handler = ngx_stream_socks_handler;

    return NGX_CONF_OK;
}

static char *
ngx_stream_socks_user_passwd(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_socks_srv_conf_t *sscf = conf;
    ngx_str_t                           *value; 
    
    value = cf->args->elts;

    sscf->name = value[1];
    sscf->passwd = value[2];

    return NGX_CONF_OK;
}
