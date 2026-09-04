#!/usr/bin/env python3
"""
Version Utility Module

WordPress plugin versions are all over the place, semver, four part,
date stamped, with and without prerelease suffixes. This normalizes them
into something we can compare in python and sort in sql.

@package KP WP VulnScan
@author Kevin Pirnie <me@kpirnie.com>
@copyright Copyright (c) 2026
"""

# setup the imports
import re

# how wide each numeric segment gets padded in the sort key, eight digits
# comfortably covers anything sane including date stamped versions
SEGMENT_WIDTH = 8

# how many segments a sort key carries, extra segments are truncated and
# short versions are padded out with zeroes
SEGMENT_COUNT = 6

# splits a version into its numeric and alphabetic runs
TOKEN_RE = re.compile(r"(\d+|[a-z]+)", re.IGNORECASE)

# prerelease markers, anything matching sorts below the plain release
PRERELEASE_RANKS = {
    "dev": 0,
    "alpha": 1,
    "a": 1,
    "beta": 2,
    "b": 2,
    "rc": 3,
    "pre": 3,
    "preview": 3,
}

# a plain release, ranks above every prerelease marker
RELEASE_RANK = 5


def parse(version: str) -> tuple[list[int], int, int]:
    """
    Break a version string into its comparable parts

    Pulls out the numeric release segments, the prerelease rank, and the
    prerelease number, ignoring the punctuation between them.

    @param version: str The raw version string
    @return tuple: The release segments, the prerelease rank, and its number
    """

    # nothing useful in an empty string
    if not version:
        return ([], RELEASE_RANK, 0)

    # strip a leading v, plenty of plugins ship "v1.2.3"
    cleaned = version.strip().lstrip("vV")

    # walk the tokens, numbers build the release until we hit a marker
    segments: list[int] = []
    rank = RELEASE_RANK
    prerelease_number = 0
    in_prerelease = False

    for token in TOKEN_RE.findall(cleaned):
        # a numeric run, it either extends the release or numbers the prerelease
        if token.isdigit():
            if in_prerelease:
                prerelease_number = int(token)
            else:
                segments.append(int(token))
            continue

        # an alphabetic run, see if it is a prerelease marker we know
        marker = token.lower()
        if marker in PRERELEASE_RANKS:
            rank = PRERELEASE_RANKS[marker]
            in_prerelease = True
            continue

        # some other suffix entirely, treat it as the end of the release
        # rather than guessing at what it means
        in_prerelease = True

    # hand back what we found
    return (segments, rank, prerelease_number)


def sort_key(version: str) -> str:
    """
    Build a lexicographically sortable key for a version

    Zero pads every segment so plain string comparison in sql orders
    versions the same way python does, which lets us index and range
    scan on it.

    @param version: str The raw version string
    @return str: A fixed width key safe to compare as a string
    """

    # break it apart first
    segments, rank, prerelease_number = parse(version)

    # pad the release out to a fixed number of segments
    padded = (segments + [0] * SEGMENT_COUNT)[:SEGMENT_COUNT]
    body = ".".join(str(segment).zfill(SEGMENT_WIDTH) for segment in padded)

    # tack the prerelease on the end so 1.0 sorts above 1.0-rc1
    return f"{body}.{rank}.{str(prerelease_number).zfill(SEGMENT_WIDTH)}"


def compare(left: str, right: str) -> int:
    """
    Compare two version strings

    Standard comparison contract, negative when left is older, zero when
    they are equivalent, positive when left is newer.

    @param left: str The first version string
    @param right: str The second version string
    @return int: -1, 0, or 1
    """

    # the sort keys are directly comparable
    left_key = sort_key(left)
    right_key = sort_key(right)

    # and back to the usual three way answer
    if left_key < right_key:
        return -1
    if left_key > right_key:
        return 1
    return 0


def in_range(
    version: str,
    from_version: str | None = None,
    from_inclusive: bool = True,
    to_version: str | None = None,
    to_inclusive: bool = True,
) -> bool:
    """
    Test whether a version falls inside an affected range

    Either bound may be missing, which means the range is open on that
    end, matching how the vulnerability feeds express things like
    "everything up to and including 1.2.3".

    @param version: str The version being tested
    @param from_version: str|None The lower bound, None for open
    @param from_inclusive: bool Whether the lower bound itself is affected
    @param to_version: str|None The upper bound, None for open
    @param to_inclusive: bool Whether the upper bound itself is affected
    @return bool: True when the version falls inside the range
    """

    # an unparseable version cannot be matched, better to miss than to
    # report a finding against something we did not understand
    if not version:
        return False

    # check the lower bound when we have one
    if from_version:
        result = compare(version, from_version)
        if result < 0 or (result == 0 and not from_inclusive):
            return False

    # then the upper bound
    if to_version:
        result = compare(version, to_version)
        if result > 0 or (result == 0 and not to_inclusive):
            return False

    # inside both bounds
    return True
