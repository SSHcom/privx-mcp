# Deployment

The MCP server is a single binary plus its configuration, given either as a TOML file or as environment variables. That makes it easy to run under whatever deployment style you already use: a service manager on a single host, a container, a Kubernetes cluster, etc.

The sections below cover some of these options.

## Systemd

systemd is the standard service manager on most Linux distributions. Besides the system services that run the operating system, it can also manage per-user services, which is a good fit for running the MCP server on a single host without root privileges.

See [systemd/README.md](./systemd/README.md) for installing the MCP server as a user service that starts automatically and restarts on failure.

## Docker

Containers are the easiest way to run the MCP server when you don't want to manage the binary on the host yourself, and they are also the basis for the Kubernetes deployment below.

### Building Docker images

Two Dockerfiles are provided, one per C library:

- `task image:glibc` builds from `deploy/docker/Dockerfile.glibc`. This is normally the one you want, as it works on most Linux platforms.
- `task image:musl` builds from `deploy/docker/Dockerfile.musl`, for platforms that don't use glibc, such as **Alpine Linux**.

[docker-compose.yml](../docker-compose.yml) is an example setup. It builds its MCP server image from `deploy/docker/Dockerfile.glibc`, which also compiles the binary, so you don't need to build the image or the binary beforehand.

### Environment variables

The images contain no configuration, so the container will not start without environment variables. The [Docker demo](./docker/demo/README.md), which runs using [docker-compose.yml](../docker-compose.yml), shows which variables are needed and how they are passed in.

## Kubernetes

For clusters, the repository provides a set of portable manifests that build on the Docker image: namespace, configuration, Deployment, Service, and Ingress. They run on any cluster.

See [k8s/README.md](./k8s/README.md) for the manifests, and [k8s/EKS-DEPLOYMENT.md](./k8s/EKS-DEPLOYMENT.md) for an Amazon EKS walkthrough using an Application Load Balancer.

---

**Overview**: [Documents Hub](../docs/README.md) | [Manual](../docs/manual/README.md)