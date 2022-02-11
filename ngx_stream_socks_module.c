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

#define NGX_STREAM_SOCKS_REPLY_REP_SUCCEED                      0x00
#define NGX_STREAM_SOCKS_REPLY_REP_SERVER_FAILURE               0x01
#define NGX_STREAM_SOCKS_REPLY_REP_NOT_ALLOWED                  0x02
#define NGX_STREAM_SOCKS_REPLY_REP_NETWORK_UNREACHABLE          0x03
#define NGX_STREAM_SOCKS_REPLY_REP_HOST_UNREACHABLE             0x04
#define NGX_STREAM_SOCKS_REPLY_REP_CONNECTION_REFUSED           0x05
#define NGX_STREAM_SOCKS_REPLY_REP_TTL_EXPIRED                  0x06
#define NGX_STREAM_SOCKS_REPLY_REP_COMMAND_NOT_SUPPORTED        0x07
#define NGX_STREAM_SOCKS_REPLY_REP_ADDRESS_TYPE_NOT_SUPPORTED   0x08
#define NGX_STREAM_SOCKS_REPLY_REP_UNASSIGNED                   0x09

#define NGX_STREAM_SOCKS_BUFFER_SIZE            128


#if defined(nginx_version) && nginx_version >= 1005008
#define __ngx_sock_ntop ngx_sock_ntop
#else
#define __ngx_sock_ntop(sa, slen, p, len, port) ngx_sock_ntop(sa, p, len, port)
#endif

#define ngx_stream_socks_parse_uint16(p)  ((p)[0] << 8 | (p)[1])

typedef struct {
    ngx_addr_t                      *addr;
    ngx_stream_complex_value_t      *value;
#if (NGX_HAVE_TRANSPARENT_PROXY)
    ngx_uint_t                       transparent; /* unsigned  transparent:1; */
#endif
} ngx_stream_upstream_local_t;

typedef struct {
    ngx_stream_complex_value_t   text;
    ngx_str_t                       name;
    ngx_str_t                       passwd;
    ngx_stream_upstream_local_t     *local;
    ngx_flag_t                       socket_keepalive;
    size_t                           buffer_size;
    ngx_msec_t                       connect_timeout;
    ngx_msec_t                       timeout;
    ngx_stream_complex_value_t          *upload_rate;
    ngx_stream_complex_value_t          *download_rate;
    ngx_uint_t                       requests;
    ngx_uint_t                       responses;
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

static void ngx_stream_socks_send_establish(ngx_stream_session_t *s, ngx_uint_t rep);
static void ngx_stream_socks_read_handler(ngx_event_t *ev);
static u_char *ngx_stream_socks_proxy_log_error(ngx_log_t *log, u_char *buf, size_t len);
static ngx_int_t ngx_stream_socks_proxy_set_local(ngx_stream_session_t *s, ngx_stream_upstream_t *u,
    ngx_stream_upstream_local_t *local);
static void ngx_stream_socks_proxy_finalize(ngx_stream_session_t *s, ngx_uint_t rc);
static ngx_int_t ngx_stream_socks_proxy_test_finalize(ngx_stream_session_t *s,
    ngx_uint_t from_upstream);
static void ngx_stream_socks_proxy_process(ngx_stream_session_t *s, ngx_uint_t from_upstream,
    ngx_uint_t do_write);
static void ngx_stream_socks_proxy_process_connection(ngx_event_t *ev, ngx_uint_t from_upstream);
static void ngx_stream_socks_proxy_downstream_handler(ngx_event_t *ev);
static void ngx_stream_socks_proxy_upstream_handler(ngx_event_t *ev);
static ngx_int_t ngx_stream_socks_get_peer(ngx_peer_connection_t *pc, void *data);
static void ngx_stream_socks_free_peer(ngx_peer_connection_t *pc, void *data, ngx_uint_t state);
static void ngx_stream_socks_proxy_init_upstream(ngx_stream_session_t *s);
static ngx_int_t ngx_stream_socks_proxy_test_connect(ngx_connection_t *c);
static void ngx_stream_socks_proxy_connect_handler(ngx_event_t *ev);
static ngx_int_t ngx_stream_socks_proxy_connect(ngx_stream_session_t *s);

static void *ngx_stream_socks_create_srv_conf(ngx_conf_t *cf);
static char *ngx_stream_socks(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_stream_socks_user_passwd(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_stream_socks_proxy_bind(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

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

    { ngx_string("socks_proxy_bind"),
      NGX_STREAM_SRV_CONF|NGX_CONF_TAKE12,
      ngx_stream_socks_proxy_bind,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("socks_proxy_socket_keepalive"),
      NGX_STREAM_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_socks_srv_conf_t, socket_keepalive),
      NULL },

    { ngx_string("socks_proxy_buffer_size"),
      NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_socks_srv_conf_t, buffer_size),
      NULL },
      
    { ngx_string("socks_proxy_connect_timeout"),
      NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_socks_srv_conf_t, connect_timeout),
      NULL },

    { ngx_string("socks_proxy_timeout"),
      NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_socks_srv_conf_t, timeout),
      NULL },

    { ngx_string("socks_proxy_upload_rate"),
      NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_stream_set_complex_value_size_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_socks_srv_conf_t, upload_rate),
      NULL },

    { ngx_string("socks_proxy_download_rate"),
      NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_stream_set_complex_value_size_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_socks_srv_conf_t, download_rate),
      NULL },

    { ngx_string("socks_proxy_requests"),
      NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_socks_srv_conf_t, requests),
      NULL },

    { ngx_string("proxy_responses"),
      NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_socks_srv_conf_t, responses),
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
    ngx_connection_t              *c;
    ngx_stream_socks_ctx_t       *ctx;

    c = s->connection;

    c->log->action = "socksing";

    ctx = ngx_pcalloc(c->pool, sizeof(ngx_stream_socks_ctx_t));
    if (ctx == NULL) {
        ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    ctx->buf = ngx_create_temp_buf(c->pool, NGX_STREAM_SOCKS_BUFFER_SIZE);

    if (ctx->buf == NULL) {
        return;
    }

    ngx_stream_set_ctx(s, ctx, ngx_stream_socks_module);

    c->read->handler = ngx_stream_socks_read_handler;

    return;
}

static void
ngx_stream_socks_send_establish(ngx_stream_session_t *s, ngx_uint_t rep)
{
    u_char                   out_buf[128];
    ngx_connection_t         *c;
    ngx_stream_socks_ctx_t   *ctx;

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_socks_module);
    c = s->connection;

    out_buf[0] = NGX_STREAM_SOCKS_VERSION;
    out_buf[1] = rep;
    out_buf[2] = 0x00;
    out_buf[3] = ctx->atype;
    out_buf[4] = 0x00;
    out_buf[5] = 0x00;
    out_buf[6] = 0x00;
    if (c->send(c, out_buf, 7) != 7) {
        ngx_stream_socks_proxy_finalize(s, NGX_STREAM_BAD_REQUEST);
    }
    return;
}

static void
ngx_stream_socks_read_handler(ngx_event_t *ev)
{
    size_t                   size, i, len;
    ssize_t                  n;
    ngx_connection_t         *c;
    ngx_stream_session_t     *s;
    ngx_stream_socks_ctx_t   *ctx;
    ngx_stream_socks_srv_conf_t *sscf;
    u_char                   *buf;
    u_char                   out_buf[128];
    ngx_sockaddr_t              dst_sockaddr;

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

        n = c->recv(c, ctx->buf->last, size);
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

        ngx_memcpy(ctx->buf->pos, ctx->buf->pos + 2 + len, size - len -2);
        ctx->buf->last = ctx->buf->last - len - 2;

        for (i = 0; i < len; i++) {
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
        if (c->send(c, out_buf, 2) != 2) {
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

        buf = buf + 2 + len;
        len = buf[1];

        ctx->passwd.data = ngx_pcalloc(c->pool, len);
        ctx->passwd.len = len;
        ngx_memcpy(ctx->passwd.data, buf + 1, len);

        len = 3 + ctx->passwd.len + ctx->name.len;
        ngx_memmove(ctx->buf->pos, ctx->buf->pos + len, size - len);
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
        if (c->send(c, out_buf, 2) != 2) {
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
            ngx_stream_socks_send_establish(s, NGX_STREAM_SOCKS_REPLY_REP_SERVER_FAILURE);
            ngx_stream_finalize_session(s, NGX_STREAM_BAD_REQUEST);
            return;
        }

        ctx->cmd = buf[1];
        if (ctx->cmd != NGX_STREAM_SOCKS_CMD_CONNECT) {
            ngx_stream_socks_send_establish(s, NGX_STREAM_SOCKS_REPLY_REP_COMMAND_NOT_SUPPORTED);
            ngx_stream_finalize_session(s, NGX_STREAM_BAD_REQUEST);
            return;
        }

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
            ngx_memcpy(&dst_sockaddr.sockaddr_in.sin_addr, buf+4, 4);
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
            ngx_memcpy(ctx->dst_addr.data, buf+5, len - 1);
            break;
        case NGX_STREAM_SOCKS_ATYPE_IPV6:
            len = 16;
            if (size < 5 + len) {
                return;
            }
            dst_sockaddr.sockaddr_in6.sin6_family = AF_INET6;
            dst_sockaddr.sockaddr_in6.sin6_port = 0;
            ngx_memcpy(&dst_sockaddr.sockaddr_in6.sin6_addr, buf+4, 16);
            ctx->dst_addr.data = ngx_pcalloc(c->pool, NGX_INET6_ADDRSTRLEN);
            ctx->dst_addr.len = ngx_sock_ntop(&dst_sockaddr.sockaddr, sizeof(struct sockaddr_in6), ctx->dst_addr.data,
                        NGX_INET6_ADDRSTRLEN, 0);
            break;
        default:
            ngx_stream_socks_send_establish(s, NGX_STREAM_SOCKS_REPLY_REP_ADDRESS_TYPE_NOT_SUPPORTED);
            ngx_stream_finalize_session(s, NGX_STREAM_BAD_REQUEST);
            return;
        }

        ctx->dst_port = ngx_stream_socks_parse_uint16(buf+4+len);
        if (ngx_stream_socks_proxy_connect(s) != NGX_OK) {
            ngx_stream_finalize_session(s, NGX_STREAM_BAD_GATEWAY);
            return;
        }

        ctx->state = socks_connecting;
        break;
    default:
        break;
    }

    return;
}

static u_char *
ngx_stream_socks_proxy_log_error(ngx_log_t *log, u_char *buf, size_t len)
{
    u_char                 *p;
    ngx_connection_t       *pc;
    ngx_stream_session_t   *s;
    ngx_stream_upstream_t  *u;

    s = log->data;

    u = s->upstream;

    p = buf;

    if (u->peer.name) {
        p = ngx_snprintf(p, len, ", upstream: \"%V\"", u->peer.name);
        len -= p - buf;
    }

    pc = u->peer.connection;

    p = ngx_snprintf(p, len,
                     ", bytes from/to client:%O/%O"
                     ", bytes from/to upstream:%O/%O",
                     s->received, s->connection->sent,
                     u->received, pc ? pc->sent : 0);

    return p;
}

static ngx_int_t
ngx_stream_socks_proxy_set_local(ngx_stream_session_t *s, ngx_stream_upstream_t *u,
    ngx_stream_upstream_local_t *local)
{
    ngx_int_t    rc;
    ngx_str_t    val;
    ngx_addr_t  *addr;

    if (local == NULL) {
        u->peer.local = NULL;
        return NGX_OK;
    }

#if (NGX_HAVE_TRANSPARENT_PROXY)
    u->peer.transparent = local->transparent;
#endif

    if (local->value == NULL) {
        u->peer.local = local->addr;
        return NGX_OK;
    }

    if (ngx_stream_complex_value(s, local->value, &val) != NGX_OK) {
        return NGX_ERROR;
    }

    if (val.len == 0) {
        return NGX_OK;
    }

    addr = ngx_palloc(s->connection->pool, sizeof(ngx_addr_t));
    if (addr == NULL) {
        return NGX_ERROR;
    }

    rc = ngx_parse_addr_port(s->connection->pool, addr, val.data, val.len);
    if (rc == NGX_ERROR) {
        return NGX_ERROR;
    }

    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                      "invalid local address \"%V\"", &val);
        return NGX_OK;
    }

    addr->name = val;
    u->peer.local = addr;

    return NGX_OK;
}

static void
ngx_stream_socks_proxy_finalize(ngx_stream_session_t *s, ngx_uint_t rc)
{
    ngx_uint_t              state;
    ngx_connection_t       *pc;
    ngx_stream_upstream_t  *u;

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "finalize stream proxy: %i", rc);

    u = s->upstream;

    if (u == NULL) {
        goto noupstream;
    }

    if (u->resolved && u->resolved->ctx) {
        ngx_resolve_name_done(u->resolved->ctx);
        u->resolved->ctx = NULL;
    }

    pc = u->peer.connection;

    if (u->state) {
        if (u->state->response_time == (ngx_msec_t) -1) {
            u->state->response_time = ngx_current_msec - u->start_time;
        }

        if (pc) {
            u->state->bytes_received = u->received;
            u->state->bytes_sent = pc->sent;
        }
    }

    if (u->peer.free && u->peer.sockaddr) {
        state = 0;

        if (pc && pc->type == SOCK_DGRAM
            && (pc->read->error || pc->write->error))
        {
            state = NGX_PEER_FAILED;
        }

        u->peer.free(&u->peer, u->peer.data, state);
        u->peer.sockaddr = NULL;
    }

    if (pc) {
        ngx_log_debug1(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
                       "close stream proxy upstream connection: %d", pc->fd);

#if (NGX_STREAM_SSL)
        if (pc->ssl) {
            pc->ssl->no_wait_shutdown = 1;
            (void) ngx_ssl_shutdown(pc);
        }
#endif

        ngx_close_connection(pc);
        u->peer.connection = NULL;
    }

noupstream:

    ngx_stream_finalize_session(s, rc);
}


static ngx_int_t
ngx_stream_socks_proxy_test_finalize(ngx_stream_session_t *s,
    ngx_uint_t from_upstream)
{
    ngx_connection_t             *c, *pc;
    ngx_log_handler_pt           handler;
    ngx_stream_upstream_t        *u;
    ngx_stream_socks_srv_conf_t  *sscf;

    sscf = ngx_stream_get_module_srv_conf(s, ngx_stream_socks_module);

    c = s->connection;
    u = s->upstream;
    pc = u->connected ? u->peer.connection : NULL;

    if (c->type == SOCK_DGRAM) {

        if (sscf->requests && u->requests < sscf->requests) {
            return NGX_DECLINED;
        }

        if (sscf->requests) {
            ngx_delete_udp_connection(c);
        }

        if (sscf->responses == NGX_MAX_INT32_VALUE
            || u->responses < sscf->responses * u->requests)
        {
            return NGX_DECLINED;
        }

        if (pc == NULL || c->buffered || pc->buffered) {
            return NGX_DECLINED;
        }

        handler = c->log->handler;
        c->log->handler = NULL;

        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "udp done"
                      ", packets from/to client:%ui/%ui"
                      ", bytes from/to client:%O/%O"
                      ", bytes from/to upstream:%O/%O",
                      u->requests, u->responses,
                      s->received, c->sent, u->received, pc ? pc->sent : 0);

        c->log->handler = handler;

        ngx_stream_socks_proxy_finalize(s, NGX_STREAM_OK);

        return NGX_OK;
    }

    /* c->type == SOCK_STREAM */

    if (pc == NULL
        || (!c->read->eof && !pc->read->eof)
        || (!c->read->eof && c->buffered)
        || (!pc->read->eof && pc->buffered))
    {
        return NGX_DECLINED;
    }

    handler = c->log->handler;
    c->log->handler = NULL;

    ngx_log_error(NGX_LOG_INFO, c->log, 0,
                  "%s disconnected"
                  ", bytes from/to client:%O/%O"
                  ", bytes from/to upstream:%O/%O",
                  from_upstream ? "upstream" : "client",
                  s->received, c->sent, u->received, pc ? pc->sent : 0);

    c->log->handler = handler;

    ngx_stream_socks_proxy_finalize(s, NGX_STREAM_OK);

    return NGX_OK;
}

static void
ngx_stream_socks_proxy_process(ngx_stream_session_t *s, ngx_uint_t from_upstream,
    ngx_uint_t do_write)
{
    char                         *recv_action, *send_action;
    off_t                        *received, limit;
    size_t                        size, limit_rate;
    ssize_t                       n;
    ngx_buf_t                    *b;
    ngx_int_t                     rc;
    ngx_uint_t                    flags, *packets;
    ngx_msec_t                    delay;
    ngx_chain_t                  *cl, **ll, **out, **busy;

    ngx_stream_upstream_t   *u;
    ngx_stream_socks_srv_conf_t *sscf;
    ngx_connection_t        *c, *pc, *src, *dst;
    ngx_log_handler_pt      handler;

    u = s->upstream;
    c = s->connection;

    pc = u->connected ? u->peer.connection : NULL;

    if (c->type == SOCK_DGRAM && (ngx_terminate || ngx_exiting)) {
        handler = c->log->handler;
        c->log->handler = NULL;

        ngx_log_error(NGX_LOG_INFO, c->log, 0, "disconnected on shutdown");

        c->log->handler = handler;

        ngx_stream_socks_proxy_finalize(s, NGX_STREAM_OK);
        return;
    }

    sscf = ngx_stream_get_module_srv_conf(s, ngx_stream_socks_module);

    if (from_upstream) {
        src = pc;
        dst = c;
        b = &u->upstream_buf;
        limit_rate = u->download_rate;
        received = &u->received;
        packets = &u->responses;
        out = &u->downstream_out;
        busy = &u->downstream_busy;
        recv_action = "socks proxying and reading from upstream";
        send_action = "socks proxying and sending to client";
    } else {
        src = c;
        dst = pc;
        b = &u->downstream_buf;
        limit_rate = u->upload_rate;
        received = &s->received;
        packets = &u->requests;
        out = &u->upstream_out;
        busy = &u->upstream_busy;
        recv_action = "socks proxying and reading from client";
        send_action = "socks proxying and sending to upstream";
    }

    for ( ;; ) {
        if (do_write && dst) {
            if (*out || *busy || dst->buffered) {
                c->log->action = send_action;

                rc = ngx_stream_top_filter(s, *out, from_upstream);

                if (rc == NGX_ERROR) {
                    ngx_stream_socks_proxy_finalize(s, NGX_STREAM_OK);
                    return;
                }

                ngx_chain_update_chains(c->pool, &u->free, busy, out,
                                      (ngx_buf_tag_t) &ngx_stream_socks_module);

                if (*busy == NULL) {
                    b->pos = b->start;
                    b->last = b->start;
                }
            }
        }

        size = b->end - b->last;

        if (size && src->read->ready && !src->read->delayed && !src->read->error) {
            if (limit_rate) {
                limit = (off_t) limit_rate * (ngx_time() - u->start_sec + 1) - *received;
                if (limit < 0) {
                    src->read->delayed = 1;
                    delay = (ngx_msec_t) (- limit * 1000 / limit_rate + 1);
                    ngx_add_timer(src->read, delay);
                    break;
                }

                if (c->type == SOCK_STREAM && (off_t) size < limit) {
                    size = (size_t) limit;
                }
            }

            c->log->action = recv_action;

            n = src->recv(src, b->last, size);

            if (n == NGX_AGAIN) {
                break;
            }

            if (n == NGX_ERROR) {
                src->read->eof = 1;
                n = 0;
            }

            if (n >= 0) {
                if (limit_rate) {
                    delay = (ngx_msec_t) (n * 1000 / limit_rate);

                    if (delay > 0) {
                        src->read->delayed = 1;
                        ngx_add_timer(src->read, delay);
                    }
                }

                if (from_upstream) {
                    if (u->state->first_byte_time == (ngx_msec_t) -1) {
                        u->state->first_byte_time = ngx_current_msec - u->start_time;
                    }
                }

                for (ll = out; *ll; ll = &(*ll)->next) { /* void */}

                cl = ngx_chain_get_free_buf(c->pool, &u->free);
                if (cl == NULL) {
                    ngx_stream_socks_proxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
                    return;
                }

                *ll = cl;
                cl->buf->pos = b->last;
                cl->buf->last = b->last + n;
                cl->buf->tag = (ngx_buf_tag_t) &ngx_stream_socks_module;

                cl->buf->temporary = (n ? 1 : 0);
                cl->buf->last_buf = src->read->eof;
                cl->buf->flush = 1;

                (*packets)++;
                *received += n;
                b->last += n;
                do_write = 1;

                continue;
            }
        }

        break;
    }

    c->log->action = "socks proxying connection";

    if (ngx_stream_socks_proxy_test_finalize(s, from_upstream) == NGX_OK) {
        return;
    }


    flags = src->read->eof ? NGX_CLOSE_EVENT : 0;
    if (ngx_handle_read_event(src->read, flags) != NGX_OK) {
        ngx_stream_socks_proxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    if (dst) {
        if (ngx_handle_write_event(dst->write, 0) != NGX_OK) {
            ngx_stream_socks_proxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }

        if (!c->read->delayed && !pc->read->delayed) {
            ngx_add_timer(c->write, sscf->timeout);
        } else if (c->write->timer_set) {
            ngx_del_timer(c->write);
        }
    }

}

static void
ngx_stream_socks_proxy_process_connection(ngx_event_t *ev, ngx_uint_t from_upstream)
{
    ngx_connection_t             *c, *pc;
    ngx_log_handler_pt            handler;
    ngx_stream_session_t         *s;
    ngx_stream_upstream_t        *u;
    ngx_stream_socks_srv_conf_t  *sscf;

    c = ev->data;
    s = c->data;
    u = s->upstream;

    if (c->close) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0, "shutdown timeout");
        ngx_stream_socks_proxy_finalize(s, NGX_STREAM_OK);
        return;
    }

    c = s->connection;
    pc = u->peer.connection;

    sscf = ngx_stream_get_module_srv_conf(s, ngx_stream_socks_module);

    if (ev->timedout) {
        ev->timedout = 0;

        if (ev->delayed) {
            ev->delayed = 0;

            if (!ev->ready) {
                if (ngx_handle_read_event(ev, 0) != NGX_OK) {
                    ngx_stream_socks_proxy_finalize(s,
                                              NGX_STREAM_INTERNAL_SERVER_ERROR);
                    return;
                }

                if (u->connected && !c->read->delayed && !pc->read->delayed) {
                    ngx_add_timer(c->write, sscf->timeout);
                }

                return;
            }

        } else {
            if (s->connection->type == SOCK_DGRAM) {

                if (sscf->responses == NGX_MAX_INT32_VALUE
                    || (u->responses >= sscf->responses * u->requests))
                {

                    /*
                     * successfully terminate timed out UDP session
                     * if expected number of responses was received
                     */

                    handler = c->log->handler;
                    c->log->handler = NULL;

                    ngx_log_error(NGX_LOG_INFO, c->log, 0,
                                  "udp timed out"
                                  ", packets from/to client:%ui/%ui"
                                  ", bytes from/to client:%O/%O"
                                  ", bytes from/to upstream:%O/%O",
                                  u->requests, u->responses,
                                  s->received, c->sent, u->received,
                                  pc ? pc->sent : 0);

                    c->log->handler = handler;

                    ngx_stream_socks_proxy_finalize(s, NGX_STREAM_OK);
                    return;
                }

                ngx_connection_error(pc, NGX_ETIMEDOUT, "upstream timed out");

                pc->read->error = 1;

                ngx_stream_socks_proxy_finalize(s, NGX_STREAM_BAD_GATEWAY);

                return;
            }

            ngx_connection_error(c, NGX_ETIMEDOUT, "connection timed out");

            ngx_stream_socks_proxy_finalize(s, NGX_STREAM_OK);

            return;
        }

    } else if (ev->delayed) {

        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0,
                       "stream connection delayed");

        if (ngx_handle_read_event(ev, 0) != NGX_OK) {
            ngx_stream_socks_proxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        }

        return;
    }

    if (from_upstream && !u->connected) {
        return;
    }

    ngx_stream_socks_proxy_process(s, from_upstream, ev->write);
}

static void
ngx_stream_socks_proxy_downstream_handler(ngx_event_t *ev)
{
    ngx_stream_socks_proxy_process_connection(ev, ev->write);
}

static void
ngx_stream_socks_proxy_upstream_handler(ngx_event_t *ev)
{
    ngx_stream_socks_proxy_process_connection(ev, !ev->write);
}

static ngx_int_t
ngx_stream_socks_get_peer(ngx_peer_connection_t *pc, void *data)
{
    return NGX_OK;
}


static void
ngx_stream_socks_free_peer(ngx_peer_connection_t *pc, void *data,
            ngx_uint_t state)
{
}

static void
ngx_stream_socks_proxy_init_upstream(ngx_stream_session_t *s)
{
    u_char                       *p;
    ngx_connection_t             *c, *pc;
    ngx_stream_upstream_t        *u;
    ngx_log_handler_pt            handler;
    ngx_stream_core_srv_conf_t   *cscf;
    ngx_stream_socks_srv_conf_t  *sscf;

    u = s->upstream;
    pc = u->peer.connection;

    cscf = ngx_stream_get_module_srv_conf(s, ngx_stream_core_module);
    sscf = ngx_stream_get_module_srv_conf(s, ngx_stream_socks_module);

    if (pc->type == SOCK_STREAM
        && cscf->tcp_nodelay
        && ngx_tcp_nodelay(pc) != NGX_OK)
    {
        ngx_stream_socks_proxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    c = s->connection;

    if (c->log->log_level >= NGX_LOG_INFO) {
        ngx_str_t  str;
        u_char     addr[NGX_SOCKADDR_STRLEN];

        str.len = NGX_SOCKADDR_STRLEN;
        str.data = addr;

        if (ngx_connection_local_sockaddr(pc, &str, 1) == NGX_OK) {
            handler = c->log->handler;
            c->log->handler = NULL;

            ngx_log_error(NGX_LOG_INFO, c->log, 0,
                          "%ssocks proxy %V connected to %V",
                          pc->type == SOCK_DGRAM ? "udp " : "",
                          &str, u->peer.name);

            c->log->handler = handler;
        }
    }

    u->state->connect_time = ngx_current_msec - u ->start_time;

    if (u->peer.notify) {
        u->peer.notify(&u->peer, u->peer.data,
                       NGX_STREAM_UPSTREAM_NOTIFY_CONNECT);
    }

    if (u->upstream_buf.start == NULL) {
        p = ngx_pcalloc(c->pool, sscf->buffer_size);
        if (p == NULL) {
            ngx_stream_socks_proxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }
        u->upstream_buf.start = p;
        u->upstream_buf.end = p + sscf->buffer_size;
        u->upstream_buf.pos = p;
        u->upstream_buf.last = p;
    }

    u->upload_rate = ngx_stream_complex_value_size(s, sscf->upload_rate, 0);
    u->download_rate = ngx_stream_complex_value_size(s, sscf->download_rate, 0);

    u->connected = 1;

    pc->read->handler = ngx_stream_socks_proxy_upstream_handler;
    pc->write->handler = ngx_stream_socks_proxy_upstream_handler;

    if (pc->read->ready) {
        ngx_post_event(pc->read, &ngx_posted_events);
    }

    ngx_stream_socks_proxy_process(s, 0, 1);

}

static ngx_int_t
ngx_stream_socks_proxy_test_connect(ngx_connection_t *c)
{
    int        err;
    socklen_t  len;

#if (NGX_HAVE_KQUEUE)

    if (ngx_event_flags & NGX_USE_KQUEUE_EVENT)  {
        err = c->write->kq_errno ? c->write->kq_errno : c->read->kq_errno;

        if (err) {
            (void) ngx_connection_error(c, err,
                                    "kevent() reported that connect() failed");
            return NGX_ERROR;
        }

    } else
#endif
    {
        err = 0;
        len = sizeof(int);

        /*
         * BSDs and Linux return 0 and set a pending error in err
         * Solaris returns -1 and sets errno
         */

        if (getsockopt(c->fd, SOL_SOCKET, SO_ERROR, (void *) &err, &len)
            == -1)
        {
            err = ngx_socket_errno;
        }

        if (err) {
            (void) ngx_connection_error(c, err, "connect() failed");
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}

static void
ngx_stream_socks_proxy_connect_handler(ngx_event_t *ev)
{
    ngx_connection_t      *c;
    ngx_stream_session_t  *s;

    c = ev->data;
    s = c->data;

    if (ev->timedout) {
        ngx_stream_socks_send_establish(s, NGX_STREAM_SOCKS_REPLY_REP_NETWORK_UNREACHABLE);
        ngx_log_error(NGX_LOG_ERR, c->log, NGX_ETIMEDOUT, "socks upstream timed out");
        ngx_stream_socks_proxy_finalize(s, NGX_STREAM_BAD_GATEWAY);
        return;
    }

    ngx_del_timer(c->write);

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "stream socks proxy connect upstream");

    if (ngx_stream_socks_proxy_test_connect(c) != NGX_OK) {
        ngx_stream_socks_proxy_finalize(s, NGX_STREAM_BAD_GATEWAY);
        return;
    }

    ngx_stream_socks_send_establish(s, NGX_STREAM_SOCKS_REPLY_REP_SUCCEED);
    ngx_stream_socks_proxy_init_upstream(s);
}


static ngx_int_t
ngx_stream_socks_proxy_connect(ngx_stream_session_t *s)
{
    u_char                           *p;
    ngx_int_t                     rc;
    ngx_connection_t             *c, *pc;
    ngx_stream_socks_ctx_t   *ctx;
    ngx_stream_socks_srv_conf_t *sscf;
    ngx_stream_upstream_t       *u;
    ngx_url_t               url;
    ngx_str_t               *host;


    c = s->connection;
    ctx = ngx_stream_get_module_ctx(s, ngx_stream_socks_module);
    sscf = ngx_stream_get_module_srv_conf(s, ngx_stream_socks_module);

    if (ctx == NULL || sscf == NULL) {
        ngx_stream_socks_send_establish(s, NGX_STREAM_SOCKS_REPLY_REP_SERVER_FAILURE);
        return NGX_ERROR;
    }

    u = ngx_pcalloc(c->pool, sizeof(ngx_stream_upstream_t));
    if (u == NULL) {
        ngx_stream_socks_send_establish(s, NGX_STREAM_SOCKS_REPLY_REP_SERVER_FAILURE);
        return NGX_ERROR;
    }

    s->upstream = u;
    s->log_handler = ngx_stream_socks_proxy_log_error;

    u->requests = 1;

    u->peer.log = c->log;
    u->peer.log_error = NGX_ERROR;

    if (ngx_stream_socks_proxy_set_local(s, u, sscf->local) != NGX_OK) {
        ngx_stream_socks_send_establish(s, NGX_STREAM_SOCKS_REPLY_REP_SERVER_FAILURE);
        return NGX_ERROR;
    }

    if (sscf->socket_keepalive) {
        u->peer.so_keepalive = 1;
    }

    u->peer.type = c->type;
    u->start_sec = ngx_time();

    c->write->handler = ngx_stream_socks_proxy_downstream_handler;
    c->read->handler = ngx_stream_socks_proxy_downstream_handler;

    s->upstream_states = ngx_array_create(c->pool, 1,
                                          sizeof(ngx_stream_upstream_state_t));
    if (s->upstream_states == NULL) {
        ngx_stream_socks_send_establish(s, NGX_STREAM_SOCKS_REPLY_REP_SERVER_FAILURE);
        return NGX_ERROR;
    }

    p = ngx_pnalloc(c->pool, sscf->buffer_size);
    if (p == NULL) {
        ngx_stream_socks_send_establish(s, NGX_STREAM_SOCKS_REPLY_REP_SERVER_FAILURE);
        return NGX_ERROR;
    }

    u->downstream_buf.start = p;
    u->downstream_buf.end = p + sscf->buffer_size;
    u->downstream_buf.pos = p;
    u->downstream_buf.last = p;

    if (c->read->ready) {
        ngx_post_event(c->read, &ngx_posted_events);
    }

    ngx_memzero(&url, sizeof(ngx_url_t));

    host = ngx_pcalloc(c->pool, ctx->dst_addr.len + 7);
    if (host == NULL) {
        ngx_stream_socks_send_establish(s, NGX_STREAM_SOCKS_REPLY_REP_SERVER_FAILURE);
        return NGX_ERROR;
    }
    ngx_memcpy(host->data, ctx->dst_addr.data, ctx->dst_addr.len);
    ngx_sprintf(host->data+ctx->dst_addr.len, ":%d", ctx->dst_port);
    host->len = ngx_strlen(host->data) - 1;
    
    url.url = *host;

    url.no_resolve = 0;

    if (ngx_parse_url(c->pool, &url) != NGX_OK) {
        if (url.err) {
            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                          "%s in upstream \"%V\"", url.err, &url.url);
        }
        ngx_stream_socks_send_establish(s, NGX_STREAM_SOCKS_REPLY_REP_HOST_UNREACHABLE);
        return NGX_ERROR;
    }

    url.port = ctx->dst_port;

    u->peer.get = ngx_stream_socks_get_peer;
    u->peer.free = ngx_stream_socks_free_peer;
    u->peer.name = &url.addrs[0].name;
    u->peer.sockaddr = url.addrs[0].sockaddr;
    u->peer.socklen = url.addrs[0].socklen;

    c->log->action = "connecting to upstream";
    u->connected = 0;
    if (u->state) {
        u->state->response_time = ngx_current_msec - u->start_time;
    }

    u->state = ngx_array_push(s->upstream_states);
    if (u->state == NULL) {
        ngx_stream_socks_send_establish(s, NGX_STREAM_SOCKS_REPLY_REP_SERVER_FAILURE);
        return NGX_ERROR;
    }

    ngx_memzero(u->state, sizeof(ngx_stream_upstream_state_t));

    u->start_time = ngx_current_msec;

    u->state->connect_time = (ngx_msec_t) -1;
    u->state->first_byte_time = (ngx_msec_t) -1;
    u->state->response_time = (ngx_msec_t) -1;

    rc = ngx_event_connect_peer(&u->peer);

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0, "socks proxy connect: %i", rc);

    if (rc == NGX_ERROR) {
        ngx_stream_socks_send_establish(s, NGX_STREAM_SOCKS_REPLY_REP_CONNECTION_REFUSED);
        return NGX_ERROR;
    }

    u->state->peer = u->peer.name;

    if (rc == NGX_DECLINED) {
        ngx_stream_socks_send_establish(s, NGX_STREAM_SOCKS_REPLY_REP_CONNECTION_REFUSED);
        return NGX_ERROR;
    }

    /* rc == NGX_OK || rc == NGX_AGAIN || rc == NGX_DONE */

    pc = u->peer.connection;

    pc->data = s;
    pc->log = c->log;
    pc->pool = c->pool;
    pc->read->log = c->log;
    pc->write->log = c->log;

    if (rc != NGX_AGAIN) {
        ngx_stream_socks_send_establish(s, NGX_STREAM_SOCKS_REPLY_REP_SUCCEED);
        ngx_stream_socks_proxy_init_upstream(s);
        return NGX_OK;
    }

    pc->read->handler = ngx_stream_socks_proxy_connect_handler;
    pc->write->handler = ngx_stream_socks_proxy_connect_handler;

    ngx_add_timer(pc->write, sscf->connect_timeout);
    return NGX_OK;
}


static void *
ngx_stream_socks_create_srv_conf(ngx_conf_t *cf)
{
    ngx_stream_socks_srv_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_stream_socks_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->local = NGX_CONF_UNSET_PTR;
    conf->socket_keepalive = 0;
    conf->buffer_size = 16384;
    conf->connect_timeout = 60000;
    conf->timeout = 60000 * 10;
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


static char *
ngx_stream_socks_proxy_bind(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_socks_srv_conf_t *sscf = conf;

    ngx_int_t                            rc;
    ngx_str_t                           *value;
    ngx_stream_complex_value_t           cv;
    ngx_stream_upstream_local_t         *local;
    ngx_stream_compile_complex_value_t   ccv;

    if (sscf->local != NGX_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (cf->args->nelts == 2 && ngx_strcmp(value[1].data, "off") == 0) {
        sscf->local = NULL;
        return NGX_CONF_OK;
    }

    ngx_memzero(&ccv, sizeof(ngx_stream_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &cv;

    if (ngx_stream_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    local = ngx_pcalloc(cf->pool, sizeof(ngx_stream_upstream_local_t));
    if (local == NULL) {
        return NGX_CONF_ERROR;
    }

    sscf->local = local;

    if (cv.lengths) {
        local->value = ngx_palloc(cf->pool, sizeof(ngx_stream_complex_value_t));
        if (local->value == NULL) {
            return NGX_CONF_ERROR;
        }

        *local->value = cv;

    } else {
        local->addr = ngx_palloc(cf->pool, sizeof(ngx_addr_t));
        if (local->addr == NULL) {
            return NGX_CONF_ERROR;
        }

        rc = ngx_parse_addr_port(cf->pool, local->addr, value[1].data,
                                 value[1].len);

        switch (rc) {
        case NGX_OK:
            local->addr->name = value[1];
            break;

        case NGX_DECLINED:
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid address \"%V\"", &value[1]);
            /* fall through */

        default:
            return NGX_CONF_ERROR;
        }
    }

    if (cf->args->nelts > 2) {
        if (ngx_strcmp(value[2].data, "transparent") == 0) {
#if (NGX_HAVE_TRANSPARENT_PROXY)
            ngx_core_conf_t  *ccf;

            ccf = (ngx_core_conf_t *) ngx_get_conf(cf->cycle->conf_ctx,
                                                   ngx_core_module);

            ccf->transparent = 1;
            local->transparent = 1;
#else
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "transparent proxying is not supported "
                               "on this platform, ignored");
#endif
        } else {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid parameter \"%V\"", &value[2]);
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}
