#!/usr/bin/env python3
"""
Secret Encryption Module

Stored secrets, api keys mostly, are encrypted at rest with a key
derived from the bootstrap secret key. A dump of the settings table on
its own gives nobody anything.

@package KP WP VulnScan
@author Kevin Pirnie <me@kpirnie.com>
@copyright Copyright (c) 2026
"""

# setup the imports
import base64
import hashlib
import logging

from cryptography.fernet import Fernet, InvalidToken

logger = logging.getLogger(__name__)

# how the encryption key is separated from the session signing key, so the
# same secret_key never gets used raw for two different purposes
KEY_INFO = b"kpwpvs-setting-encryption-v1"


class SecretBox:
    """
    Encrypts and decrypts stored secrets

    Wraps fernet, which gives us authenticated encryption so a tampered
    ciphertext fails loudly instead of decrypting to garbage.
    """

    def __init__(self, secret_key: str) -> None:
        """
        Build a secret box from the bootstrap secret key

        @param secret_key: str The configured secret key
        @throws ValueError: When no secret key has been configured
        """

        # without this we cannot store secrets at all, and silently storing
        # them in the clear would be worse than refusing
        if not secret_key:
            raise ValueError("a secret key is required before secrets can be stored, set KPWPVS_SECRET_KEY")

        # derive a separate 32 byte key rather than using the raw value
        derived = hashlib.blake2b(secret_key.encode("utf-8"), key=KEY_INFO, digest_size=32).digest()
        self._fernet = Fernet(base64.urlsafe_b64encode(derived))

    def encrypt(self, value: str) -> str:
        """
        Encrypt a secret for storage

        @param value: str The plaintext secret
        @return str: The ciphertext, safe to store as text
        """

        # empty stays empty, an unset secret is not a secret
        if not value:
            return ""

        return self._fernet.encrypt(value.encode("utf-8")).decode("ascii")

    def decrypt(self, value: str) -> str:
        """
        Decrypt a stored secret

        A secret encrypted under a different secret key cannot be
        recovered, which is the point, so that case comes back empty
        with a warning rather than throwing.

        @param value: str The stored ciphertext
        @return str: The plaintext, or empty when it cannot be decrypted
        """

        # nothing stored, nothing to hand back
        if not value:
            return ""

        # a failure here almost always means secret_key changed
        try:
            return self._fernet.decrypt(value.encode("ascii")).decode("utf-8")
        except InvalidToken, ValueError:
            logger.warning("a stored secret could not be decrypted, has the secret key changed?")
            return ""
