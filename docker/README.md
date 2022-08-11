
**NOTE**: `Dockerfile.aarch64` is not working for now.

## Build the docker image
```
docker build -f Dockerfile.x86_64 . -t simple-http-server
```

## Run the docker image
```
docker run -it --init --rm -p 8000:8000 -v `pwd`:/var/www/html/ simple-http-server --upload
```
