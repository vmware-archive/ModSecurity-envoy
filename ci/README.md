# Envoy CI
For more details see [envoy/ci/README.md](https://github.com/envoyproxy/envoy/blob/master/ci/README.md)

# Build image for Modsecurity-envoy

The build image for ModSecurity is different than the regular envoy's build image. 
(because of dependencies on additional libraries, see ./build_container/build_container_modsecurity_ubuntu.sh)
Thus we need to rebuild the image.
To build a local clone of the build image you can make changes to files such as
build_container.sh locally and then run:

```bash
DISTRO=ubuntu
cd ci/build_container
LINUX_DISTRO="${DISTRO}" CIRCLE_SHA1=modsecurity_v1 ./docker_build.sh  # Wait patiently for quite some time
```

This builds the Ubuntu based `envoyproxy/envoy-build-ubuntu` image

# Building and running tests as a developer

You can either use envoy-filter-example's ./ci/do_ci.sh to create a run simple build and tests.

```bash
sudo IMAGE_NAME=envoyproxy/envoy-build-ubuntu IMAGE_ID=modsecurity_v1 ./ci/run_envoy_docker.sh './ci/do_ci.sh build'
```

Or you can use do_envoy_ci.sh which acts as a proxy for envoy's do_ci.sh (for more information on options see envoy/ci/do_ci.sh)

```bash
sudo IMAGE_NAME=envoyproxy/envoy-build-ubuntu IMAGE_ID=modsecurity_v1 ./ci/run_envoy_docker.sh './ci/do_envoy_ci.sh bazel.release'
```