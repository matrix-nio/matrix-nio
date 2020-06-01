# To build the image, run `docker build` command from the root of the
# repository:
#
#    docker build -f docker/Dockerfile .
#
# There is an optional PYTHON_VERSION build argument which sets the
# version of python to build against. For example:
#
#    docker build -f docker/Dockerfile --build-arg PYTHON_VERSION=3.8 .
#
#
# And an optional LIBOLM_VERSION build argument which sets the
# version of libolm to build against. For example:
#
#    docker build -f docker/Dockerfile --build-arg LIBOLM_VERSION=3.1.4 .
#

##
## Creating a builder container
##

# We use an initial docker container to build all of the runtime dependencies,
# then transfer those dependencies to the container we're going to ship,
# before throwing this one away
ARG PYTHON_VERSION=3.8
FROM docker.io/python:${PYTHON_VERSION}-alpine3.11 as builder

##
## Build libolm for matrix-nio e2e support
##

# Install libolm build dependencies
ARG LIBOLM_VERSION=3.1.4
RUN apk add --no-cache \
    make \
    cmake \
    gcc \
    g++ \
    git \
    libffi-dev \
    python3-dev

# Build libolm at the specified version
#
# This will build libolm and place it at /libolm
# This will also build the libolm python bindings and place them at /python-libs
# We will later copy contents from both of these folders to the runtime container
COPY docker/build_and_install_libolm.sh /scripts/
RUN /scripts/build_and_install_libolm.sh ${LIBOLM_VERSION} /python-libs

# Now that libolm is installed, install matrix-nio with e2e dependencies
# We again install to /python-libs
RUN pip install --prefix="/python-libs" --no-warn-script-location \
    "matrix-nio[e2e]"

##
## Creating the runtime container
##

# Create the container we'll actually ship. We need to copy libolm and any
# python dependencies that we built above to this container
FROM docker.io/python:${PYTHON_VERSION}-alpine3.11

# Copy python dependencies from the "builder" container
COPY --from=builder /python-libs /usr/local

# Copy libolm from the "builder" container
COPY --from=builder /usr/local/lib/libolm* /usr/local/lib/

# Install any native runtime dependencies
RUN apk add --no-cache \
    libstdc++
