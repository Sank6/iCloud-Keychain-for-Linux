"""Common bases for the package's exceptions."""


class AppleError(RuntimeError):
    """Base for every error raised against an Apple service or its wire formats."""


class SessionError(AppleError):
    """Local secret storage problem: the stored session/vault cannot be read or its key is gone."""
