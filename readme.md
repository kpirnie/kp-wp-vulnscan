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

An open source WordPress plugin vulnerability scanner and reporter.

It tracks the wordpress.org plugin repository, matches what it finds against known vulnerability feeds, ranks plugins by how many issues they have accumulated, and reports on all of it. Runs as a podman container, scheduled from the host.

## Status

Early development. Built in stages:

- [x] repo skeleton, configuration, logging
- [x] database schema and migrations
- [x] wordpress.org catalog crawler
- [x] vulnerability feeds (Wordfence Intelligence, NVD/CVE)
- [x] matcher and priority scoring
- [x] reporters (database, json, html, webhook)
- [ ] web interface
- [ ] authentication and roles
- [ ] container and pod manifests

Phase two adds local source scanning of plugin zips, optional AI assisting, and .

## Configuration

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

Any of these can be supplied as a file instead, which is how you feed a podman secret in without it landing in the process environment:

```
KPWPVS_DATABASE_PASSWORD_FILE=/run/secrets/db_password
```

## Usage

```

```

## Requirements


## License

The data in this repository is provided under the **MIT License**. 
You can view the full license text in the [LICENSE](LICENSE) file in this repository.

The underlying primary vulnerability information is sourced from Wordfence Intelligence and NVD/CVE and is subject to their terms and conditions.

## Disclaimer

This database is provided "as is", without warranty of any kind, express or implied. The maintainers of this repository are not responsible for any actions taken based on the information provided herein. Always verify critical information with the authoritative source (Wordfence) and follow responsible disclosure practices.
