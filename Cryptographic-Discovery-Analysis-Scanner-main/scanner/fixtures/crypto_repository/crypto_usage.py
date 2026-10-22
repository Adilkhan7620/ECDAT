"""Deliberate, non-executable cryptographic API references for ECDAT tests."""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.ciphers import algorithms
import hashlib


def rsa_example() -> object:
    """Reference an RSA API without generating or storing a key."""
    return rsa.generate_private_key


def ecdsa_example() -> object:
    """Reference an ECDSA API without signing data."""
    return ec.ECDSA


def ecdh_example() -> object:
    """Reference an ECDH API without deriving a shared secret."""
    return ec.ECDH


def aes_example() -> object:
    """Reference an AES API without constructing a cipher or key."""
    return algorithms.AES


def hashing_example() -> object:
    """Reference SHA-256 APIs without processing real data."""
    return hashlib.sha256, hashes.SHA256
