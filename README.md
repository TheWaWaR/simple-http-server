# How to use?

``` bash
# Install Rust
curl https://sh.rustup.rs -sSf | sh

# Install simple-http-server
cargo install simple-http-server
rehash
simple-http-server -h
```

# Features
- [x] Specify listen address (ip, port)
- [x] Specify running threads
- [x] Specify directory root
- [x] Pretty log
- [x] Nginx like directory view (directory entries, link, filesize, modfiled date)
- [x] Breadcrumb navigation
- [x] Guess mime type
- [x] (default disabled) Automatic render index page [index.html, index.htm]
- [x] (default disabled) Upload file
- [ ] Basic Authentication (by password)
