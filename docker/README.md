The Dockerfile is copied from: https://github.com/k4yt3x/simple-http-server/blob/master/Dockerfile
LICENS: BSD 2-Clause "Simplified" License
   please see https://github.com/k4yt3x/simple-http-server/blob/master/LICENSE for more details

**NOTE**: `Dockerfile.aarch64` is not working for now.

## Build the docker image
```
docker build --build-arg BRANCH=master -f Dockerfile.x86_64 . -t simple-http-server
```

Both Dockerfiles enable the `tls` feature, so the resulting image supports `--cert` and `--certpass`.

## Run the docker image
```
docker run -it --init --rm -p 8000:8000 -v `pwd`:/var/www/html/ simple-http-server --upload
```
