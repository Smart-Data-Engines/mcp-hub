"""Optional OTLP tracing with identifiers only, never arguments or credentials."""

from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

_provider: TracerProvider | None = None


def configure(endpoint: str) -> TracerProvider | None:
    global _provider
    if not endpoint:
        return None
    if _provider is None:
        _provider = TracerProvider(resource=Resource.create({"service.name": "mcp-hub"}))
        url = endpoint.rstrip("/")
        if not url.endswith("/v1/traces"):
            url += "/v1/traces"
        _provider.add_span_processor(
            BatchSpanProcessor(
                OTLPSpanExporter(endpoint=url, timeout=2), export_timeout_millis=3000
            )
        )
        trace.set_tracer_provider(_provider)
    return _provider
