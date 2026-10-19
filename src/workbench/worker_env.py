"""Explicit environment filtering for subprocesses that do not need LLM credentials."""

AGENT_PROVIDER_ENV = (
    "OHSCANNER_LLM_BASE_URL",
    "OHSCANNER_LLM_MODEL",
    "OHSCANNER_LLM_API_KEY",
    "OHSCANNER_LLM_PROXY_URL",
)


def worker_child_environment(source, *, allow_agent_provider=False):
    """Copy the process environment, forwarding provider settings only to Agent children."""
    environment = {key: value for key, value in source.items()
                   if not key.startswith("OHSCANNER_LLM_")}
    if allow_agent_provider:
        for key in AGENT_PROVIDER_ENV:
            if key in source:
                environment[key] = source[key]
    return environment


def remove_agent_provider_environment(environment):
    """Remove all LLM settings from a process before it executes unrelated work."""
    for key in tuple(environment):
        if key.startswith("OHSCANNER_LLM_"):
            environment.pop(key, None)
