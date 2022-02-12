# ngx_stream_socks_module

### Build
 ./configure --add-module=../ngx_stream_socks_module --with-stream

### Use
```
stream {     
    server {         
        listen     0.0.0.0:22345;
        socks;     
    }
}
```