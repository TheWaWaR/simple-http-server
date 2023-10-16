
The Dockerfile is copied from: https://github.com/k4yt3x/simple-http-server/blob/master/Dockerfile
LICENS: BSD 2-Clause "Simplified" License
   please see https://github.com/k4yt3x/simple-http-server/blob/master/LICENSE for more details

**NOTE**: `Dockerfile.aarch64` is not working for now.

## Build the docker image with `v0.6.3`
```
docker build --build-arg BRANCH=v0.6.3 -f Dockerfile.x86_64 . -t simple-http-server
```

## Run the docker image
```
docker run -it --init --rm -p 8000:8000 -v `pwd`:/var/www/html/ simple-http-server --upload
```
