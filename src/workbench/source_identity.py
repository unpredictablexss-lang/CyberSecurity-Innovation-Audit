"""Stable source identifiers for repository mirrors and cache records."""
from urllib.parse import urlsplit


def repository_source_id(url):
    """Return a host-qualified repository identity without credentials or .git suffix."""
    try:
        parsed = urlsplit(url)
        host = (parsed.hostname or "").lower()
        port = parsed.port
    except (TypeError, ValueError) as exc:
        raise ValueError("invalid repository source URL") from exc
    if not host or not parsed.path:
        raise ValueError("invalid repository source URL")
    authority = host + ((":" + str(port)) if port is not None else "")
    path = parsed.path.rstrip("/")
    if path.endswith(".git"):
        path = path[:-4]
    return parsed.scheme.lower() + "://" + authority + path
