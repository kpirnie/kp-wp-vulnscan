# kp-wp-vulnscan

An open source WordPress plugin vulnerability scanner and reporter.

It tracks the wordpress.org plugin repository, matches what it finds
against known vulnerability feeds, ranks plugins by how many issues
they have accumulated, and reports on all of it. Runs as a podman
container, scheduled from the host.

## status

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

## configuration

Copy `config/config.example.yaml` to `config/config.yaml`, or mount it
into the container at `/config/config.yaml`. Every setting can also be
supplied as an environment variable using the `KPWPVS_` prefix and the
dotted path uppercased with underscores:

```
KPWPVS_DATABASE_PASSWORD=secret
KPWPVS_WEB_PORT=9090
KPWPVS_FEEDS_NVD_API_KEY=...
```

The environment always wins over the file.

## usage

```
kpwpvs scan              # the full pipeline, this is what cron calls
kpwpvs crawl [--full]    # crawl the wordpress.org plugin repository
kpwpvs feeds             # refresh the vulnerability feeds
kpwpvs match             # match vulnerabilities against the catalog
kpwpvs report            # generate reports for the most recent run
kpwpvs db init|upgrade|status
kpwpvs web               # run the web interface
```

## requirements

Python 3.14.7 or newer, MariaDB or MySQL.

## License

The data in this repository is provided under the **MIT License**. 
You can view the full license text in the [LICENSE](LICENSE) file in this repository.

The underlying primary vulnerability information is sourced from Wordfence Intelligence and NVD/CVE and is subject to their terms and conditions.

## Disclaimer

This database is provided "as is", without warranty of any kind, express or implied. The maintainers of this repository are not responsible for any actions taken based on the information provided herein. Always verify critical information with the authoritative source (Wordfence) and follow responsible disclosure practices.
