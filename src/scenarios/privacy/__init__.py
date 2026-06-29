from scenarios.privacy import (
    aggregation_gateway,
    location_granularity,
    pseudonymous_forum,
    selective_access_control,
    strip_invisible_metadata,
)

SCENARIOS = [
    location_granularity.SCENARIO,
    pseudonymous_forum.SCENARIO,
    aggregation_gateway.SCENARIO,
    strip_invisible_metadata.SCENARIO,
    selective_access_control.SCENARIO,
]
