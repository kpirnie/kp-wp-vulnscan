# KP WordPress Vulnerability Scan

An open source WordPress plugin vulnerability scanner and reporter.

It tracks the wordpress.org plugin repository, matches what it finds
against known vulnerability feeds, ranks plugins by how many issues
they have accumulated, and reports on all of it. Runs as a podman
container, scheduled from the host.

## Status

Early development. Built in stages:

- [x] repo skeleton, configuration, logging
- [ ] database schema and migrations
- [ ] wordpress.org catalog crawler
- [ ] vulnerability feeds (Wordfence Intelligence, NVD/CVE)
- [ ] matcher and priority scoring
- [ ] reporters (database, json, html, webhook)
- [ ] web interface
- [ ] authentication and roles
- [ ] container and pod manifests

Phase two adds local source scanning of plugin zips, optionally
AI assisted.

## Configuration

There is no config file. The environment carries the database connection
and the secret key, both set in `docker-compose.yaml` so there is no
`.env` to carry around. Everything else lives in the `settings` and
`feeds` tables and is managed from the web interface, so endpoints and
api keys can be changed without a redeploy.

```yaml
environment:
  KPWPVS_DATABASE_HOST: db
  KPWPVS_DATABASE_PORT: 3306
  KPWPVS_DATABASE_NAME: kpwpvs
  KPWPVS_DATABASE_USER: kpwpvs
  KPWPVS_DATABASE_PASSWORD: secret

  # signs sessions and encrypts stored api keys, generate one with:
  #   python3 -c "import secrets; print(secrets.token_urlsafe(48))"
  KPWPVS_SECRET_KEY: ...
```

Any of these can be supplied as a file instead, which is how you feed a
podman secret in without it landing in the process environment:

```
KPWPVS_DATABASE_PASSWORD_FILE=/run/secrets/db_password
```

The three vulnerability feeds are seeded on first migration and are
editable from the interface, endpoint included, because these do move.

## Usage

```
kpwpvs scan              # the full pipeline, this is what cron calls
kpwpvs crawl [--full]    # crawl the wordpress.org plugin repository
kpwpvs feeds             # refresh the vulnerability feeds
kpwpvs match             # match vulnerabilities against the catalog
kpwpvs report            # generate reports for the most recent run
kpwpvs db init|upgrade|status
kpwpvs web               # run the web interface
```

## Requirements

Podman/Docker (recommended) Python 3.14.7 or newer, MariaDB or MySQL.

## License

The data in this repository is provided under the **MIT License**. 
You can view the full license text in the [LICENSE](LICENSE) file in this repository.

The underlying primary vulnerability information is sourced from Wordfence Intelligence and NVD/CVE and is subject to their terms and conditions.

## Disclaimer

This database is provided "as is", without warranty of any kind, express or implied. The maintainers of this repository are not responsible for any actions taken based on the information provided herein. Always verify critical information with the authoritative source (Wordfence) and follow responsible disclosure practices.
