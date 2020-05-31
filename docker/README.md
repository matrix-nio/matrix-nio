# Docker

The provided docker base image is based on alpine, and comes with libolm and libolm python3
bindings installed. This image can then be built on top of for projects that use matrix-nio.

## Building the Image

To build the image from source, use the following `docker build` command from
the repo's root:

```sh
docker build -t poljar/matrix-nio:latest -f docker/Dockerfile .
```

You can also customise the version of libolm and python that is bundled in the container
using the following build arguments.

To customise the python version, set `PYTHON_VERSION`:

```sh
docker build -t poljar/matrix-nio:latest -f docker/Dockerfile --build-arg PYTHON_VERSION=3.8 .
```

To customise the libolm version, set `LIBOLM_VERSION`:

```sh
docker build -t poljar/matrix-nio:latest -f docker/Dockerfile --build-arg LIBOLM_VERSION=3.1.4 .
```
