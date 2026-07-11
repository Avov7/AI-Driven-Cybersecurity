"""
OpenTelemetry tracer shared across all VulnOps modules.
Exports spans to Jaeger via OTLP HTTP.
"""
import os
from opentelemetry import trace
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

_provider: TracerProvider | None = None


def _init() -> TracerProvider:
    endpoint = os.getenv("OTLP_ENDPOINT", "http://jaeger:4318/v1/traces")
    resource = Resource.create({"service.name": "vulnops-ai"})
    provider = TracerProvider(resource=resource)
    exporter = OTLPSpanExporter(endpoint=endpoint)
    provider.add_span_processor(BatchSpanProcessor(exporter))
    trace.set_tracer_provider(provider)
    return provider


def get_tracer(name: str = "vulnops") -> trace.Tracer:
    global _provider
    if _provider is None:
        try:
            _provider = _init()
        except Exception:
            # If Jaeger is not reachable, fall back to a no-op provider
            _provider = TracerProvider()
    return trace.get_tracer(name)
