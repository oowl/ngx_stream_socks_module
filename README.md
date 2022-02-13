# ngx_stream_socks_module
## Description
Socks5 proxy server based on nginx stream module implementation.

## Installation

``` 
$ ./configure --add-module=/path/ngx_stream_dns_proxy_module --with-stream

```

## Configuration directives

### `socks`

- **syntax**: `socks`
- **default**: `-`
- **context**: `server`

Set socks server in current server context.

### `socks_user_passwd`

- **syntax**: `socks_user_passwd user passwd`
- **default**: `-`
- **context**: `stream`,`server`

Add username/password authentication to socks5 server. Adding this conf is like opening the socks5 username/password Authentication. You can use this conf to add multilateral username/password authentication for many times.

### `socks_proxy_bind`

- **syntax**: `socks_proxy_bind address [transparent] | off;`
- **default**: `-`
- **context**: `stream`,`server`

Makes outgoing connections to a socks proxied server originate from the specified local IP address. Parameter value can contain variables (1.11.2). The special value off cancels the effect of the socks_proxy_bind directive inherited from the previous configuration level, which allows the system to auto-assign the local IP address.

### `socks_proxy_socket_keepalive`

- **syntax**: `socks_proxy_socket_keepalive on | off;`
- **default**: `socks_proxy_socket_keepalive off;`
- **context**: `stream`,`server`

Configures the “TCP keepalive” behavior for outgoing connections to a socks proxied server. By default, the operating system’s settings are in effect for the socket. If the directive is set to the value “on”, the SO_KEEPALIVE socket option is turned on for the socket.

### `socks_proxy_buffer_size`

- **syntax**: `socks_proxy_buffer_size size;`
- **default**: `socks_proxy_buffer_size 16k;`
- **context**: `stream`,`server`

Sets the size of the buffer used for reading data from the proxied server. Also sets the size of the buffer used for reading data from the client.

### `socks_proxy_connect_timeout`

- **syntax**: `socks_proxy_connect_timeout time;`
- **default**: `socks_proxy_buffer_size 60s;`
- **context**: `stream`,`server`

Defines a timeout for establishing a connection with a proxied server.

### `socks_proxy_timeout`

- **syntax**: `socks_proxy_timeout time;`
- **default**: `socks_proxy_timeout 10m;`
- **context**: `stream`,`server`

Sets the timeout between two successive read or write operations on client or proxied server connections. If no data is transmitted within this time, the connection is closed.

### `socks_proxy_upload_rate`

- **syntax**: `socks_proxy_upload_rate rate;`
- **default**: `socks_proxy_upload_rate 0;`
- **context**: `stream`,`server`

Limits the speed of reading the data from the client. The rate is specified in bytes per second. The zero value disables rate limiting. The limit is set per a connection, so if the client simultaneously opens two connections, the overall rate will be twice as much as the specified limit.

### `socks_proxy_download_rate`

- **syntax**: `socks_proxy_download_rate rate;`
- **default**: `socks_proxy_download_rate 0;`
- **context**: `stream`,`server`

Limits the speed of reading the data from the proxied server. The rate is specified in bytes per second. The zero value disables rate limiting. The limit is set per a connection, so if nginx simultaneously opens two connections to the proxied server, the overall rate will be twice as much as the specified limit.

## Variables

### `$socks_connect_addr`
socks connect contain addr and port

### `$socks_name`
socks auth user name in current connection

### `$socks_passwd`
socks auth password in current connection

## Usage
```
stream {
    log_format socks 'socks: $socks_connect_addr $socks_name $socks_passwd';
    server {         
        listen     0.0.0.0:22345;
        socks;
        socks_user_passwd <user1> <password1>;
        socks_user_passwd <user2> <password2>;
        access_log socks_access.log socks;
    }
}
```



