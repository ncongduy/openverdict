from prometheus_client import REGISTRY


def sample(name: str, **labels: str) -> float:
    """Current value of a Prometheus sample in the default registry (0.0 if absent)."""
    return REGISTRY.get_sample_value(name, labels) or 0.0
