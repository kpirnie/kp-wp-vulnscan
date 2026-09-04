# KP WP VulnScan
#
# One container: the scanner, the interface, and mariadb. Self contained
# by design, so a single podman run with one volume gets you a working
# install.
#
# Three stages. The css builder and the wheel builder both throw their
# toolchains away, so neither node nor a compiler ends up in the runtime
# image.

# --- stage 1: the stylesheet ------------------------------------------
# tailwind needs node, and node has no business in the runtime image
FROM node:22-trixie-slim AS css

WORKDIR /build
COPY kpwpvs/web/assets/app.css ./kpwpvs/web/assets/app.css
COPY kpwpvs/web/templates ./kpwpvs/web/templates

# tailwind scans the templates for the classes actually used, so they have
# to be present here or the output is nearly empty
RUN npm install --no-save tailwindcss@4.3.3 @tailwindcss/cli@4.3.3 \
 && npx @tailwindcss/cli \
      --input  kpwpvs/web/assets/app.css \
      --output /build/app.css \
      --minify


# --- stage 2: the python wheels ---------------------------------------
FROM python:3.14.7-slim-trixie AS wheels

# everything we need has a manylinux wheel, but build tools are here in
# case a future dependency does not
RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential libffi-dev \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY requirements.txt .
RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install --no-cache-dir --upgrade pip \
 && /opt/venv/bin/pip install --no-cache-dir -r requirements.txt


# --- stage 3: the runtime ---------------------------------------------
FROM python:3.14.7-slim-trixie

ARG MARIADB_SERIES=12.3
ARG S6_OVERLAY_VERSION=3.2.1.0
ARG TARGETARCH=amd64

LABEL org.opencontainers.image.title="KP WP VulnScan" \
      org.opencontainers.image.description="WordPress core and plugin vulnerability scanner and reporter" \
      org.opencontainers.image.source="https://github.com/kpirnie/kp-wp-vulnscan" \
      org.opencontainers.image.licenses="MIT"

ENV DEBIAN_FRONTEND=noninteractive \
    PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    S6_BEHAVIOUR_IF_STAGE2_FAILS=2 \
    S6_KEEP_ENV=1 \
    S6_CMD_WAIT_FOR_SERVICES_MAXTIME=0 \
    KPWPVS_DATABASE_HOST=127.0.0.1 \
    KPWPVS_DATABASE_PORT=3306 \
    KPWPVS_DATABASE_NAME=kpwpvs \
    KPWPVS_DATABASE_USER=kpwpvs

# mariadb from upstream rather than debian's, because debian trixie ships
# 11.8 and we want the 12.3 lts series
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        ca-certificates curl gnupg xz-utils tzdata cron gosu; \
    curl -fsSL https://mariadb.org/mariadb_release_signing_key.pgp \
        -o /etc/apt/keyrings/mariadb.pgp; \
    echo "deb [signed-by=/etc/apt/keyrings/mariadb.pgp] https://mirror.mariadb.org/repo/${MARIADB_SERIES}/debian trixie main" \
        > /etc/apt/sources.list.d/mariadb.sources.list; \
    apt-get update; \
    apt-get install -y --no-install-recommends mariadb-server mariadb-client; \
    apt-get purge -y --auto-remove gnupg; \
    rm -rf /var/lib/apt/lists/* /var/lib/mysql; \
    mkdir -p /var/lib/mysql /run/mysqld; \
    chown -R mysql:mysql /var/lib/mysql /run/mysqld

# s6 supervises mysqld and the interface together, so signals and reaping
# behave and podman stop actually stops things
RUN set -eux; \
    case "${TARGETARCH}" in \
        amd64) S6_ARCH=x86_64 ;; \
        arm64) S6_ARCH=aarch64 ;; \
        *) echo "unsupported architecture ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    curl -fsSL "https://github.com/just-containers/s6-overlay/releases/download/v${S6_OVERLAY_VERSION}/s6-overlay-noarch.tar.xz" \
        | tar -C / -Jxpf -; \
    curl -fsSL "https://github.com/just-containers/s6-overlay/releases/download/v${S6_OVERLAY_VERSION}/s6-overlay-${S6_ARCH}.tar.xz" \
        | tar -C / -Jxpf -

COPY --from=wheels /opt/venv /opt/venv
COPY --from=css /build/app.css /app/kpwpvs/web/static/app.css

WORKDIR /app
COPY kpwpvs ./kpwpvs
COPY migrations ./migrations
COPY alembic.ini pyproject.toml requirements.txt readme.md LICENSE ./
COPY container/rootfs /

RUN set -eux; \
    /opt/venv/bin/pip install --no-cache-dir --no-deps -e .; \
    chmod -R +x /etc/s6-overlay/s6-rc.d /usr/local/bin; \
    mkdir -p /data /reports

# /var/lib/mysql has to be a mount or the catalog dies with the container.
# the entrypoint refuses to start without it rather than writing into the
# container layer where it would silently vanish on the next pull
VOLUME ["/var/lib/mysql", "/data", "/reports"]

EXPOSE 8080

# a working install answers this, a broken one does not
HEALTHCHECK --interval=60s --timeout=10s --start-period=90s --retries=3 \
    CMD /usr/local/bin/kpwpvs-health

ENTRYPOINT ["/init"]
