# KP WP VulnScan
#
# One container: the scanner, the interface, and mariadb. Self contained
# by design, so a single run with one volume gets you a working install.
#
# Built on the official mariadb image rather than installing mariadb onto
# a python one. That image is maintained by the people who write the
# database, pins an exact version, and needs no third party apt repo.
#
# Python comes from an astral standalone build rather than a distro
# package, because ubuntu noble has no 3.14 and deadsnakes only carries
# 3.14.6. This project pins 3.14.7 deliberately.

ARG MARIADB_TAG=latest
ARG PYTHON_VERSION=3.14.7


# --- stage 1: the stylesheet ------------------------------------------
# tailwind needs node, and node has no business in the runtime image
FROM docker.io/node:22-trixie-slim AS css

WORKDIR /build
COPY kpwpvs/web/assets/app.css ./kpwpvs/web/assets/app.css
COPY kpwpvs/web/templates ./kpwpvs/web/templates

# tailwind scans the templates for the classes actually used, so they have
# to be present here or the output is nearly empty
RUN npm install --no-save @tailwindcss/cli@4.3.3 tailwindcss@4.3.3 \
    && npx @tailwindcss/cli \
    --input  kpwpvs/web/assets/app.css \
    --output /build/app.css \
    --minify


# --- stage 2: python and the wheels -----------------------------------
# built on the same base as the runtime, so the interpreter and every
# compiled wheel are linked against the glibc they will actually run on
FROM docker.io/mariadb:${MARIADB_TAG} AS python
ARG PYTHON_VERSION

COPY --from=ghcr.io/astral-sh/uv:0.12.9 /uv /usr/local/bin/uv

ENV UV_PYTHON_INSTALL_DIR=/opt/python \
    UV_LINK_MODE=copy \
    UV_NO_CACHE=1

WORKDIR /build
COPY requirements.txt .

# the interpreter, then the environment, then the dependencies. every one
# of them has a manylinux wheel, so nothing is compiled here. the venv is
# seeded because uv does not install pip by default, and the runtime
# stage needs it to install this project itself
RUN set -eux; \
    uv python install "${PYTHON_VERSION}"; \
    uv venv --seed /opt/venv --python "${PYTHON_VERSION}"; \
    uv pip install --python /opt/venv/bin/python --requirement requirements.txt; \
    /opt/venv/bin/python --version


# --- stage 3: the runtime ---------------------------------------------
FROM docker.io/mariadb:${MARIADB_TAG}
ARG S6_OVERLAY_VERSION=3.2.1.0
ARG TARGETARCH=amd64

LABEL org.opencontainers.image.title="KP WP VulnScan" \
    org.opencontainers.image.description="WordPress core and plugin vulnerability scanner and reporter" \
    org.opencontainers.image.source="https://github.com/kpirnie/kp-wp-vulnscan" \
    org.opencontainers.image.licenses="MIT"

ENV DEBIAN_FRONTEND=noninteractive \
    PATH="/opt/venv/bin:$PATH" \
    PYTHONPATH=/app \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    S6_BEHAVIOUR_IF_STAGE2_FAILS=2 \
    S6_KEEP_ENV=1 \
    S6_CMD_WAIT_FOR_SERVICES_MAXTIME=0 \
    KPWPVS_DATABASE_HOST=127.0.0.1 \
    KPWPVS_DATABASE_PORT=3306 \
    KPWPVS_DATABASE_NAME=kpwpvs \
    KPWPVS_DATABASE_USER=kpwpvs

# the base image carries mariadb, gosu and tar already. cron is for the
# optional built in schedule, curl is only needed to fetch s6 below
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates cron curl xz-utils; \
    rm -rf /var/lib/apt/lists/*

# s6 supervises mariadbd and the interface together, so signals and
# reaping behave and a stop actually stops things
RUN set -eux; \
    case "${TARGETARCH}" in \
    amd64) S6_ARCH=x86_64 ;; \
    arm64) S6_ARCH=aarch64 ;; \
    *) echo "unsupported architecture ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    curl -fsSL "https://github.com/just-containers/s6-overlay/releases/download/v${S6_OVERLAY_VERSION}/s6-overlay-noarch.tar.xz" \
    | tar -C / -Jxpf -; \
    curl -fsSL "https://github.com/just-containers/s6-overlay/releases/download/v${S6_OVERLAY_VERSION}/s6-overlay-${S6_ARCH}.tar.xz" \
    | tar -C / -Jxpf -; \
    apt-get purge -y --auto-remove curl; \
    rm -rf /var/lib/apt/lists/*

# the interpreter and the environment, at the paths the venv expects
COPY --from=python /opt/python /opt/python
COPY --from=python /opt/venv /opt/venv
COPY --from=css /build/app.css /app/kpwpvs/web/static/app.css

WORKDIR /app
COPY kpwpvs ./kpwpvs
COPY migrations ./migrations
COPY alembic.ini pyproject.toml requirements.txt readme.md LICENSE ./
COPY container/rootfs /

# deliberately not a pip install of this project. an editable install
# would drag the build backend down from pypi at image build time, which
# means the build needs working network access to install code that is
# already sitting in the layer. a launcher on the path does the same job
# with no network and no build step, and keeps /app as the project root
# so the migrations directory resolves next to it
RUN set -eux; \
    printf '%s\n' '#!/bin/sh' 'exec /opt/venv/bin/python -m kpwpvs "$@"' > /usr/local/bin/kpwpvs; \
    chmod +x /usr/local/bin/kpwpvs; \
    chmod -R +x /etc/s6-overlay/s6-rc.d /usr/local/bin; \
    mkdir -p /data /reports /run/mysqld; \
    chown mysql:mysql /run/mysqld; \
    /opt/venv/bin/python -c "import kpwpvs; print('kpwpvs', kpwpvs.__version__)"

# note the base image declares VOLUME /var/lib/mysql and a child image
# cannot undo that, so every run gets a volume whether one was asked for
# or not. the entrypoint checks whether it is an anonymous one instead,
# because an anonymous volume is data you will lose without noticing

EXPOSE 8080

# the base image's entrypoint expects to be pid 1 and to exec mariadbd.
# ours runs several things under supervision instead
ENTRYPOINT ["/init"]
CMD []
