#!/usr/bin/env python3
"""
Settings Service Module

Reads and writes the settings table, falling back to the registry
defaults for anything not stored. Secrets are decrypted on the way out
and encrypted on the way in, so callers never handle ciphertext.

@package KP WP VulnScan
@author Kevin Pirnie <me@kpirnie.com>
@copyright Copyright (c) 2026
"""

# setup the imports
import json
import logging
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from kpwpvs.core.crypto import SecretBox
from kpwpvs.core.settings import SETTINGS_BY_KEY, SettingDef, SettingType, defaults
from kpwpvs.models import Setting

logger = logging.getLogger(__name__)


class SettingsService:
    """
    Typed access to the settings table

    Loads everything once and caches it, because the pipeline reads the
    same handful of values over and over inside tight loops.
    """

    def __init__(self, session: Session, secret_box: SecretBox | None = None) -> None:
        """
        Build a settings service around a session

        @param session: Session The database session to read and write through
        @param secret_box: SecretBox|None Needed only when secrets are touched
        """

        self._session = session
        self._secret_box = secret_box
        self._cache: dict[str, Any] | None = None

    def _load(self) -> dict[str, Any]:
        """
        Load every stored setting into the cache

        Anything stored that the registry no longer knows about is left
        alone rather than deleted, a downgrade should not lose settings.

        @return dict: The raw stored values, keyed by setting key
        """

        # only hit the database the once
        if self._cache is None:
            rows = self._session.execute(select(Setting)).scalars().all()
            self._cache = {row.key: row.value for row in rows}

        return self._cache

    def invalidate(self) -> None:
        """
        Drop the cache so the next read hits the database

        Called after a write, and by the interface when somebody else
        might have changed something.

        @return None
        """

        self._cache = None

    def _coerce(self, definition: SettingDef, raw: str | None) -> Any:
        """
        Turn a stored value back into its declared type

        @param definition: SettingDef The registry entry for this setting
        @param raw: str|None The stored json encoded value
        @return Any: The value as its declared type, or the default
        """

        # nothing stored, use the default
        if raw is None or raw == "":
            return definition.default

        # everything non secret is stored json encoded so the type survives
        try:
            value = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            logger.warning("setting %s holds a value that will not decode, using the default", definition.key)
            return definition.default

        # a stored value of the wrong shape is worse than the default
        try:
            if definition.type is SettingType.INTEGER:
                return int(value)
            if definition.type is SettingType.FLOAT:
                return float(value)
            if definition.type is SettingType.BOOLEAN:
                return bool(value)
            if definition.type is SettingType.CHOICE:
                return value if value in definition.choices else definition.default
        except (TypeError, ValueError):
            logger.warning("setting %s holds a %s that will not coerce, using the default", definition.key, type(value))
            return definition.default

        return value

    def get(self, key: str) -> Any:
        """
        Get one setting, typed

        Secrets come back decrypted, so treat the result accordingly.

        @param key: str The dotted setting key
        @return Any: The stored value, or the registry default
        @throws KeyError: When the key is not in the registry
        """

        # the registry is the authority on what exists
        definition = SETTINGS_BY_KEY.get(key)
        if definition is None:
            raise KeyError(f"unknown setting '{key}'")

        raw = self._load().get(key)

        # secrets take the other path entirely
        if definition.is_secret:
            if not raw:
                return definition.default
            if self._secret_box is None:
                raise RuntimeError(f"setting '{key}' is a secret and no secret box was provided")
            return self._secret_box.decrypt(raw)

        return self._coerce(definition, raw)

    def get_many(self, group: str) -> dict[str, Any]:
        """
        Get every setting in a group

        Handy for the pipeline stages, which each want one group's worth
        of settings up front.

        @param group: str The group name
        @return dict: The settings in that group, keyed by their short name
        """

        # strip the group prefix off the keys, callers already know it
        result: dict[str, Any] = {}
        for key, definition in SETTINGS_BY_KEY.items():
            if definition.group == group and not definition.is_secret:
                result[key.split(".", 1)[1]] = self.get(key)

        return result

    def set(self, key: str, value: Any, user_id: int | None = None) -> None:
        """
        Store one setting

        Coerces to the declared type before storing, so a bad value is
        rejected here rather than surfacing somewhere strange later.

        @param key: str The dotted setting key
        @param value: Any The value to store
        @param user_id: int|None Who changed it, for the settings page
        @return None
        @throws KeyError: When the key is not in the registry
        @throws ValueError: When the value does not fit the declared type
        """

        # the registry is the authority on what exists
        definition = SETTINGS_BY_KEY.get(key)
        if definition is None:
            raise KeyError(f"unknown setting '{key}'")

        # secrets get encrypted, everything else json encoded
        if definition.is_secret:
            if self._secret_box is None:
                raise RuntimeError(f"setting '{key}' is a secret and no secret box was provided")
            stored = self._secret_box.encrypt(str(value or ""))
        else:
            stored = json.dumps(self._validate(definition, value))

        # update in place, or insert when the registry gained a key that
        # the seed migration never wrote
        row = self._session.execute(select(Setting).where(Setting.key == key)).scalar_one_or_none()
        if row is None:
            row = Setting(key=key, is_secret=definition.is_secret)
            self._session.add(row)

        row.value = stored
        row.updated_by_id = user_id
        row.updated_by_at = datetime.now()

        # next read picks up what we just wrote
        self.invalidate()

    def _validate(self, definition: SettingDef, value: Any) -> Any:
        """
        Coerce and range check a value against its definition

        @param definition: SettingDef The registry entry for this setting
        @param value: Any The incoming value
        @return Any: The coerced value
        @throws ValueError: When the value does not fit
        """

        # coerce to the declared type first
        try:
            if definition.type is SettingType.INTEGER:
                value = int(value)
            elif definition.type is SettingType.FLOAT:
                value = float(value)
            elif definition.type is SettingType.BOOLEAN:
                value = bool(value)
            elif definition.type is SettingType.STRING:
                value = str(value)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"setting '{definition.key}' expects a {definition.type}") from exc

        # a choice has to actually be one of the choices
        if definition.type is SettingType.CHOICE and value not in definition.choices:
            raise ValueError(f"setting '{definition.key}' must be one of {', '.join(definition.choices)}")

        # and the numeric bounds where they apply
        if definition.minimum is not None and value < definition.minimum:
            raise ValueError(f"setting '{definition.key}' must be at least {definition.minimum}")
        if definition.maximum is not None and value > definition.maximum:
            raise ValueError(f"setting '{definition.key}' must be at most {definition.maximum}")

        return value

    def all_defaults(self) -> dict[str, Any]:
        """
        Every registry default

        @return dict: Setting keys mapped to their default values
        """

        return defaults()
