# How it looks like?

<img src="./screenshot.png" width="50%" height="50%">

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
- [x] Windows support (with colored log)
- [x] Specify listen address (ip, port)
- [x] Specify running threads
- [x] Specify root directory
- [x] Pretty log
- [x] Nginx like directory view (directory entries, link, filesize, modfiled date)
- [x] Breadcrumb navigation
- [x] (default enabled) Guess mime type
- [x] (default enabled) HTTP cache control
  - Sending Last-Modified / ETag
  - Replying 304 to If-Modified-Since
- [x] (default enabled) Partial request
  - Accept-Ranges: bytes([ByteRangeSpec; length=1])
  - [Range, If-Range, If-Match] => [Content-Range, 206, 416]
- [x] (default disabled) Automatic render index page [index.html, index.htm]
- [x] (default disabled) Upload file
- [x] (default disabled) HTTP Basic Authentication (by username:password)
- [x] Sort by: filename, filesize, modifled
- [x] HTTPS support
