#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>

#define NGX_STREAM_SOCKS_VERSION                 0x05
#define NGX_STREAM_SOCKS_RESERVED                0x00
#define NGX_STREAM_SOCKS_AUTH_METHOD_COUNT       0x01
#define NGX_STREAM_SOCKS_AUTH_NO_AUTHENTICATION  0x00
#define NGX_STREAM_SOCKS_CMD_CONNECT             0x01
#define NGX_STREAM_SOCKS_ADDR_IPv4               0x01
#define NGX_STREAM_SOCKS_ADDR_IPv6               0x04
#define NGX_STREAM_SOCKS_ADDR_DOMAIN_NAME        0x03

#define 

static u_char ngx_stream_socks_auth_sucess[] = {
    NGX_HT,
    NGX_HTTP_SOCKS_AUTH_METHOD_COUNT,
    NGX_HTTP_SOCKS_AUTH_NO_AUTHENTICATION
};

typedef struct {
    ngx_stream_complex_value_t   text;
} ngx_stream_socks_srv_conf_t;


typedef struct {
    enum {
        sock_preauth = 0,
        socks_auth,
        socks_connect,
        socks_done
    } state;
    ngx_str_t   name;
    ngx_str_t   passwd;
    ngx_chain_t                 *out;
} ngx_stream_socks_ctx_t;


static void ngx_stream_socks_handler(ngx_stream_session_t *s);
static void ngx_stream_socks_write_handler(ngx_event_t *ev);
static void ngx_stream_socks_read_handler(ngx_event_t *ev);

static void *ngx_stream_socks_create_srv_conf(ngx_conf_t *cf);
static char *ngx_stream_socks(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


static ngx_command_t  ngx_stream_socks_commands[] = {

    { ngx_string("socks"),
      NGX_STREAM_SRV_CONF|NGX_CONF_NOARGS,
      ngx_stream_socks,
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
        return;
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
    ngx_connection_t         *c;
    ngx_stream_session_t     *s;
    ngx_stream_socks_ctx_t  *ctx;

    u_char                  buf[256];
    ngx_uint_t              len;

    c = ev->data;
    s = c->data;

    if (ev->timedout) {
        ngx_connection_error(c, NGX_ETIMEDOUT, "connection timed out");
        ngx_stream_finalize_session(s, NGX_STREAM_OK);
        return;
    }

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_socks_module);

    switch (ctx->state)
    {
    case sock_preauth:
        
    case socks_auth:
        // read auth
        c->recv(c, buf, 2);
        if (buf[0] != NGX_STREAM_SOCKS_VERSION && buf[1] == 0) {
            ngx_stream_finalize_session(s, NGX_STREAM_FORBIDDEN);
            return;
        }
        // read name
        len = buf[1];
        c->recv(c, buf, len);
        ctx->name.data = ngx_pcalloc(c->pool, len);
        ctx->name.len = len;
        ngx_memcpy(ctx->name.data, buf, len);

        c->recv(c, buf, 1);
        len = buf[0];
        c->recv(c, buf, len);
        ctx->passwd.data = ngx_pcalloc(c->pool, len);
        ctx->passwd.len = len;
        ngx_memcpy(ctx->passwd.data, buf, len);


        /* code */
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
