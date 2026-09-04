# KP WordPress Vulnerability Scan

**REPO**

[![Build Main](https://img.shields.io/github/actions/workflow/status/kpirnie/kp-wp-vulnscan/build.yml?branch=main&label=Main&logo=github&logoColor=white&labelColor=000&style=for-the-badge)](https://github.com/kpirnie/kp-wp-vulnscan/actions?query=workflow%3A%22Build+and+Push+Docker+Image%22+branch%3Amain)
[![GitHub Issues](https://img.shields.io/github/issues/kpirnie/kp-wp-vulnscan?style=for-the-badge&logo=github&color=006400&logoColor=white&labelColor=000)](https://github.com/kpirnie/kp-wp-vulnscan/issues)
[![GitHub Security](https://img.shields.io/badge/Security-View-6495ED?link=https://github.com/kpirnie/kp-wp-vulnscan/security&logoColor=white&style=for-the-badge&labelColor=000&logo=data:image/svg%2bxml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgd2lkdGg9IjI0IiBoZWlnaHQ9IjI0IiBmaWxsPSJub25lIiBzdHJva2U9IndoaXRlIiBzdHJva2Utd2lkdGg9IjIiPjxwYXRoIGQ9Ik0xMiAyTDQgNXY2LjA5YzAgNS4wNSAzLjQxIDkuNzYgOCAxMC45MSA0LjU5LTEuMTUgOC01Ljg2IDgtMTAuOTFWNWwtOC0zeiIvPjwvc3ZnPg==)](https://github.com/kpirnie/kp-wp-vulnscan/security)
[![Last Commit](https://img.shields.io/github/last-commit/kpirnie/kp-wp-vulnscan?style=for-the-badge&labelColor=000)](https://github.com/kpirnie/kp-wp-vulnscan/commits/main)
[![License: MIT](https://img.shields.io/badge/License-MIT-orange.svg?style=for-the-badge&logo=opensourceinitiative&logoColor=white&labelColor=000)](LICENSE)

**STACK**

[![Python](https://img.shields.io/badge/Python-3.14-3776AB?logo=python&logoColor=white&style=for-the-badge&labelColor=000)](https://python.org)
[![MariaDB](https://img.shields.io/badge/Min.%20MariaDB-11.4-003545?logo=mariadb&logoColor=white&style=for-the-badge&labelColor=000)](https://mariadb.org/)
[![WordPress](https://img.shields.io/badge/Up%20To%20WP-7.1-3858e9?logo=wordpress&logoColor=white&style=for-the-badge&labelColor=000)](https://wordpress.org)
[![Debian](https://img.shields.io/badge/Base-Debian%20Trixie-A81D33?logo=debian&logoColor=white&style=for-the-badge&labelColor=000)](https://www.debian.org/)

**PLUG**

[![Kevin Pirnie](https://img.shields.io/badge/-KevinPirnie.com-000d2d?style=for-the-badge&labelColor=000&logoColor=white&logo=data:image/svg%2Bxml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0ibm9uZSIgc3Ryb2tlPSJ3aGl0ZSIgc3Ryb2tlLXdpZHRoPSIxLjgiIHN0cm9rZS1saW5lY2FwPSJyb3VuZCIgc3Ryb2tlLWxpbmVqb2luPSJyb3VuZCI+CiAgPGNpcmNsZSBjeD0iMTIiIGN5PSIxMiIgcj0iMTAiLz4KICA8ZWxsaXBzZSBjeD0iMTIiIGN5PSIxMiIgcng9IjQuNSIgcnk9IjEwIi8+CiAgPGxpbmUgeDE9IjIiIHkxPSIxMiIgeDI9IjIyIiB5Mj0iMTIiLz4KICA8bGluZSB4MT0iNC41IiB5MT0iNi41IiB4Mj0iMTkuNSIgeTI9IjYuNSIvPgogIDxsaW5lIHgxPSI0LjUiIHkxPSIxNy41IiB4Mj0iMTkuNSIgeTI9IjE3LjUiLz4KPC9zdmc+Cg==)](https://kevinpirnie.com/)

An open source WordPress vulnerability scanner and reporter, for core and for
the plugin repository.

It tracks every release of WordPress core and the whole wordpress.org plugin
catalog, matches both against known vulnerability feeds, ranks everything by
the issues it has accumulated, and reports on it. One container, one volume,
scheduled from the host.

Core leads every report. A vulnerable core makes everything under it moot.

## What it finds

Real figures from a full run at the time of writing, not projections. Your
own numbers will differ as the repository and the feeds move:

| | |
|---|---|
| Plugins in the wordpress.org repository | 71,538 |
| Also catalogued, because a feed named them | 8,600 plugins and 2,154 themes |
| Core releases tracked | 884, of which **859** wordpress.org itself flags insecure |
| Vulnerability records | 39,695 across 46,402 affected version ranges |
| Repository plugins with a known vulnerability | 7,485 |
| Open findings against **currently published** plugin versions | 1,395 |

Two findings worth knowing before you run it:

- **Half the repository is abandoned.** 35,609 of 71,538 plugins have not been
  updated in two years or more, including some with hundreds of thousands of
  installs. They are flagged, and weighted accordingly, because nothing is
  coming to save them.
- **The current core release is not clean either.** Two issues affect every
  version WordPress has ever shipped, so no installation is unaffected by
  them. You cannot patch your way out of those, which is exactly why they are
  worth surfacing.

## Quick start

```bash
git clone https://github.com/kpirnie/kp-wp-vulnscan.git
cd kp-wp-vulnscan

# set a database password and a secret key in docker-compose.yaml first
podman compose up -d
```

Then create the first account and sign in at <http://localhost:8080>:

```bash
podman exec -it kpwpvs sh -c 'printf "%s\n" "your-password" | kpwpvs user add you --role admin'
```

The first run has an empty catalog. Fill it:

```bash
podman exec kpwpvs kpwpvs scan
```

That takes a few minutes the first time, because it seeds the whole catalog.
Every run after is incremental and takes seconds.

### Name the volume

The container refuses to start on an anonymous volume. The catalog takes
minutes to rebuild and the findings carry work people have done by hand, and
an anonymous volume is discarded by a `compose down -v` or a `rm -v` without
a prompt. Name one instead:

```yaml
volumes:
  - kpwpvs-db:/var/lib/mysql
```

Set `KPWPVS_ALLOW_EPHEMERAL_DB=true` if you genuinely want throwaway storage.

## Scheduling

Weekly is the intent. The Wordfence feed only changes every few hours and
rate-limits rapid re-pulls, so anything more often than nightly is wasted
effort.

From the host, which is the recommended way:

```cron
0 3 * * 1  podman exec kpwpvs kpwpvs scan
```

Or let the container schedule itself by setting `KPWPVS_SCHEDULE` to a crontab
expression.

## Configuration

Only two things come from the environment, and both live in
`docker-compose.yaml` so there is no `.env` to carry around:

```yaml
environment:
  # the database. host, port, name and user have sensible defaults baked
  # into the image, so in practice only the password matters
  KPWPVS_DATABASE_PASSWORD: "..."

  # signs sessions and encrypts stored api keys. generate one with:
  #   python3 -c "import secrets; print(secrets.token_urlsafe(48))"
  KPWPVS_SECRET_KEY: "..."
```

Any of them can be supplied as a file instead, which keeps the value out of
the process environment entirely:

```
KPWPVS_DATABASE_PASSWORD_FILE=/run/secrets/db_password
```

**Everything else lives in the database** and is managed from the Settings
page: crawler behaviour, scoring weights, report output, notifications, and
the AI provider. Set `KPWPVS_DATABASE_EMBEDDED=false` to point at an existing
MariaDB or MySQL rather than the bundled one.

## Data sources

The feeds are rows in the database, not configuration, so their endpoints are
editable from the interface. That is not hypothetical: the Wordfence v2 feed
was retired during development and started answering `410`, and being able to
point at the replacement without a redeploy is the whole reason.

| Feed | Role | Key |
|---|---|---|
| [Wordfence Intelligence](https://www.wordfence.com/threat-intel/) | Primary | Required |
| [NVD](https://nvd.nist.gov/) | Secondary | Optional, raises the rate limit |
| [CVE Services](https://www.cve.org/) | Tertiary, keyless fallback | None |

Wordfence is the only feed that carries the wordpress.org slug, so it is the
only one that ties a vulnerability to a package directly. The other two
recover a slug from reference URLs where they can — measured at about 1% of a
real window — and otherwise enrich by CVE id. A relevance filter drops the
rest, because an NVD window carries roughly 10,000 CVEs of which a few hundred
have anything to do with WordPress.

Add your Wordfence key on the Feeds page, or from the command line:

```bash
podman exec -i kpwpvs kpwpvs feeds --set-key wordfence <<< "your-api-key"
```

Keys are encrypted at rest with a key derived from `KPWPVS_SECRET_KEY`, and
the interface only ever shows whether one is stored, never its value.

## Roles

| Role | Can |
|---|---|
| **admin** | Everything, including users, settings and feeds |
| **manager** | Read everything, and work findings |
| **user** | Read |

## Reports

The database summary is always written. JSON and HTML are written only when
`/reports` is actually mounted, and skipped silently when it is not. A webhook
fires only when one is configured and something met the minimum severity, in
Slack, Discord or generic JSON shape.

Notification counts deliberately exclude historical core findings. Including
them reports tens of thousands of issues against releases from 2004 that
nobody runs, which is the fastest way to get an alert muted.

## Commands

```
kpwpvs scan                      # the whole pipeline, this is what cron calls
kpwpvs crawl [--full|--core-only|--skip-core]
kpwpvs feeds [--list|--source X|--set-key X]
kpwpvs match                     # match vulnerabilities against the catalog
kpwpvs report [--stdout]         # report without running the pipeline
kpwpvs db upgrade|status|wait|downgrade --revision X
kpwpvs user add|list|passwd|role
kpwpvs web
```

Passwords and API keys are read from stdin, never from arguments, so they stay
out of shell history and the process table.

## How it works

1. **Crawl** — walks the wordpress.org catalog, checkpointing as it goes so an
   interrupted seed resumes rather than restarting. Later runs walk the
   updated ordering only until they reach ground already covered.
2. **Feeds** — pulls each enabled source in priority order. One being down or
   unkeyed does not stop the others.
3. **Match** — joins the feeds onto the catalog.
4. **Report** — one payload, rendered as JSON, HTML and a notification, so
   they can never disagree about what a run found.

Core and plugins are matched differently on purpose. For a plugin only the
currently published version matters, because that is what anyone installing it
gets. Everybody runs some older core, so core is matched per release and a
finding names the version it is about.

Priority is scored separately from findings, over the whole issue history. A
plugin with a long record of holes stays near the top of the scan queue even
when today's release happens to be clean.

Packages the feeds name but the free repository does not carry — commercial
plugins, and ones withdrawn after a disclosure — are catalogued as `premium`
rather than dropped. That is 8,600 plugins and 2,154 themes.

## Requirements

Nothing but a container runtime to run it. The image is built on the official
`mariadb` image, so MariaDB 12.3.3 comes from the people who write it, and
Python 3.14.7 is an Astral standalone build rather than a distribution
package, since neither Ubuntu nor deadsnakes carries that patch level.

For development: Python 3.14.7, a MariaDB or MySQL to point at, and the
standalone Tailwind CLI if you are changing the stylesheet.

```bash
python3.14 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/pip install -e .

export KPWPVS_DATABASE_HOST=127.0.0.1 KPWPVS_DATABASE_PASSWORD=... KPWPVS_SECRET_KEY=...
kpwpvs db upgrade
kpwpvs web
```

Lint and format with `ruff check kpwpvs migrations` and
`ruff format kpwpvs migrations`; CI enforces both. Rebuild the stylesheet with
`./kpwpvs/web/assets/build.sh`.

## Status

Phase one is complete:

- [x] repo skeleton, configuration, logging
- [x] database schema and migrations
- [x] wordpress.org catalog crawler
- [x] WordPress core release tracking and per-release matching
- [x] vulnerability feeds (Wordfence Intelligence, NVD, CVE Services)
- [x] matcher and priority scoring
- [x] reporters (database, JSON, HTML, webhook)
- [x] web interface
- [x] authentication and roles
- [x] container image, compose file and CI

Phase two: local source scanning of plugin archives, optionally AI assisted
with a pluggable provider. Phase three: themes, which the schema already
accommodates — theme vulnerability records are being stored today, they simply
have no catalog to join to yet.

## License

The data in this repository is provided under the **MIT License**. 
You can view the full license text in the [LICENSE](LICENSE) file in this repository.

The underlying primary vulnerability information is sourced from Wordfence Intelligence and NVD/CVE and is subject to their terms and conditions.

## Disclaimer

This database is provided "as is", without warranty of any kind, express or implied. The maintainers of this repository are not responsible for any actions taken based on the information provided herein. Always verify critical information with the authoritative source (Wordfence) and follow responsible disclosure practices.
