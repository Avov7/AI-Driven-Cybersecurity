"""
Non-blocking Kafka publisher.
Initialised in a background thread so a slow Kafka startup never
blocks the VulnOps app.  All publish calls are fire-and-forget.
"""
import json
import os
import threading

_producer = None
_ready = False
_lock = threading.Lock()


def _init() -> None:
    global _producer, _ready
    try:
        from kafka import KafkaProducer
        import time
        time.sleep(5)  # wait for Kafka to be fully ready
        bootstrap = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
        prod = KafkaProducer(
            bootstrap_servers=bootstrap,
            value_serializer=lambda v: json.dumps(v, default=str).encode("utf-8"),
            request_timeout_ms=5_000,
        )
        with _lock:
            _producer = prod
            _ready = True
        print("[kafka_pub] Connected to Kafka ✓")
    except Exception as exc:
        print(f"[kafka_pub] Kafka not available ({exc})")


# Kick off the connection attempt in a daemon thread
threading.Thread(target=_init, daemon=True).start()


def publish(topic: str, data: dict) -> None:
    """Publish *data* to *topic*.  Never raises; silently drops if unavailable."""
    with _lock:
        prod = _producer
        ok = _ready
    if not ok or prod is None:
        return
    try:
        prod.send(topic, data)
    except Exception:
        pass
