"""Versioned, demand-driven shared fact providers for reviewed detectors."""

from dataclasses import dataclass
from time import perf_counter, process_time

from .facts import build_syntax_facts


@dataclass(frozen=True)
class FactProvider:
    provider_id: str
    version: str
    output_fact: str
    input_facts: tuple[str, ...]
    supported_languages: tuple[str, ...]
    cost_tier: str
    build: object


class FactProviderRegistry:
    def __init__(self, providers=()):
        self._providers = {}
        self._outputs = {}
        for provider in providers:
            self.register(provider)

    def register(self, provider):
        if not isinstance(provider, FactProvider):
            raise TypeError("provider must be a FactProvider")
        if provider.provider_id in self._providers:
            raise ValueError("duplicate fact provider id")
        if provider.output_fact in self._outputs:
            raise ValueError("duplicate fact provider output")
        if provider.cost_tier not in {"low", "medium", "high"}:
            raise ValueError("invalid fact provider cost tier")
        self._providers[provider.provider_id] = provider
        self._outputs[provider.output_fact] = provider.provider_id

    def plan(self, required_facts):
        """Select providers only for explicitly requested facts and dependencies."""
        pending = list(sorted(set(required_facts)))
        selected, missing = {}, set()
        while pending:
            fact = pending.pop()
            if fact == "ast" or fact in selected:
                continue
            provider_id = self._outputs.get(fact)
            if provider_id is None:
                missing.add(fact)
                continue
            provider = self._providers[provider_id]
            selected[provider_id] = provider
            pending.extend(provider.input_facts)
        return tuple(selected[key] for key in sorted(selected)), tuple(sorted(missing))

    def build(self, ast_by_file, required_facts, languages):
        providers, missing = self.plan(required_facts)
        available = {"ast": ast_by_file}
        metrics = {"provider_count": 0, "provider_wall_seconds": 0.0,
                   "provider_cpu_seconds": 0.0, "providers": []}
        language_set = set(languages)
        for provider in providers:
            if not language_set.intersection(provider.supported_languages):
                missing = tuple(sorted(set(missing) | {provider.output_fact}))
                continue
            wall, cpu = perf_counter(), process_time()
            try:
                result = provider.build(available)
            except Exception:
                # A failed fact remains absent. The runner will mark detectors
                # requiring it blocked and preserve unknown coverage.
                missing = tuple(sorted(set(missing) | {provider.output_fact}))
                continue
            metrics["provider_wall_seconds"] += perf_counter() - wall
            metrics["provider_cpu_seconds"] += process_time() - cpu
            metrics["provider_count"] += 1
            metrics["providers"].append({"id": provider.provider_id,
                                         "version": provider.version,
                                         "output_fact": provider.output_fact})
            available[provider.output_fact] = result
        return available, missing, metrics


DEFAULT_FACT_PROVIDERS = FactProviderRegistry((
    FactProvider(
        provider_id="syntax_facts_v1", version="1.0.0",
        output_fact="facts_v1", input_facts=("ast",),
        supported_languages=("c", "cpp", "js", "ts", "arkts"),
        cost_tier="low", build=lambda facts: build_syntax_facts(facts["ast"]),
    ),
))
