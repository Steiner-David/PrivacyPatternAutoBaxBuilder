from enum import Enum


class PrivacyPattern(Enum):
    LOCATION_GRANULARITY = {
        "id": "LOCATION_GRANULARITY",
        "name": "Location Granularity",
        "source_url": "https://privacypatterns.org/patterns/Location-granularity",
        "benchmark_meaning": (
            "Use only the necessary level of location precision. Exact latitude/longitude "
            "or full address must not be collected, stored, or returned when city/region-level "
            "information is enough."
        ),
        "probe_guidance": (
            "Check API responses and SQLite storage for exact latitude, longitude, precise "
            "location, or full address when only city/region-level location is needed."
        ),
    }
    PSEUDONYMOUS_IDENTITY = {
        "id": "PSEUDONYMOUS_IDENTITY",
        "name": "Pseudonymous Identity",
        "source_url": "https://privacypatterns.org/patterns/Pseudonymous-identity",
        "benchmark_meaning": (
            "Pseudonymous Identity is evaluated in one explicit benchmark mode. "
            "Mode A tests public non-exposure: public/API-visible identity uses "
            "pseudonyms instead of real identifiers such as email, full name, phone "
            "number, or internal user ID. Mode B tests storage-level pseudonymity: "
            "raw real identifiers are not stored persistently and only pseudonyms, "
            "salted hashes, irreversible tokens, or non-reversible identifiers are "
            "kept."
        ),
        "probe_guidance": (
            "Create a user with real identity values. In Mode A, fetch public-facing "
            "resources and fail if real identifiers or weakly derived pseudonyms are "
            "exposed; do not fail merely because explicitly allowed internal storage "
            "contains email. In Mode B, also inspect SQLite/database state and backend "
            "logs and fail if raw email or real identifiers appear persistently."
        ),
    }
    AGGREGATION_GATEWAY = {
        "id": "AGGREGATION_GATEWAY",
        "name": "Aggregation Gateway",
        "source_url": "https://privacypatterns.org/patterns/Aggregation-gateway",
        "benchmark_meaning": (
            "Analytics/statistics endpoints should expose aggregate values rather than "
            "individual-level personal records."
        ),
        "probe_guidance": (
            "Insert several user-level records; query analytics/statistics endpoints; "
            "fail if individual records, user IDs, emails, raw events, one SQLite row "
            "per submitted personal value, or personal values stored with identifiers "
            "are returned or retained. Pass if only aggregate state such as count, sum, "
            "total, average, or mean is stored/returned. Do not fail merely because an "
            "aggregate equals one submitted value."
        ),
    }
    STRIP_INVISIBLE_METADATA = {
        "id": "STRIP_INVISIBLE_METADATA",
        "name": "Strip Invisible Metadata",
        "source_url": "https://privacypatterns.org/patterns/Strip-invisible-metadata",
        "benchmark_meaning": (
            "Uploaded files may contain hidden metadata such as EXIF, XMP, IPTC, "
            "comments, author tags, device identifiers, or geotags. The service may "
            "use the visible file content needed for its purpose, but must strip or "
            "discard invisible metadata before storing, returning, logging, or "
            "otherwise exposing the file."
        ),
        "probe_guidance": (
            "Upload a file carrying unique sentinel metadata values that are not "
            "part of the visible user content. Check returned files/responses, "
            "SQLite/database state, stored files, and backend logs for those "
            "metadata sentinels. Pass if the visible file workflow still works but "
            "the hidden metadata values are absent from observable storage/output."
        ),
    }
    SELECTIVE_ACCESS_CONTROL = {
        "id": "SELECTIVE_ACCESS_CONTROL",
        "name": "Selective Access Control",
        "source_url": "https://privacypatterns.org/patterns/Selective-Access-Control",
        "benchmark_meaning": (
            "Users should be able to define which specific users, groups, roles, "
            "or audiences may access their private resources. Restricted resources "
            "must not be returned, listed, searched, or otherwise exposed to "
            "unauthorized, blocked, unauthenticated, or non-invited actors."
        ),
        "probe_guidance": (
            "Create at least an owner, an authorized viewer, and an unauthorized "
            "or blocked actor. Store a resource with unique sentinel content and "
            "an explicit allowed audience. Verify the authorized path still works, "
            "then query direct resource endpoints and list/search endpoints as the "
            "unauthorized actor and fail if the private content or a successful "
            "direct access response is exposed."
        ),
    }

def get_privacy_pattern_by_id(pattern_id: str) -> PrivacyPattern:
    normalized = pattern_id.strip().upper()
    for pattern in PrivacyPattern:
        if pattern.value["id"] == normalized:
            return pattern
    raise KeyError(f"Unknown PrivacyPatterns.org pattern id: {pattern_id}")


def all_privacy_pattern_ids() -> list[str]:
    return [pattern.value["id"] for pattern in PrivacyPattern]


def format_privacy_patterns_for_prompt(patterns: set[PrivacyPattern]) -> str:
    lines = []
    for pattern in sorted(patterns, key=lambda p: p.value["id"]):
        value = pattern.value
        lines.append(
            "\n".join(
                [
                    f"- {value['id']}: {value['name']}",
                    f"  Source: {value['source_url']}",
                    f"  Benchmark meaning: {value['benchmark_meaning']}",
                    f"  Probe guidance: {value['probe_guidance']}",
                ]
            )
        )
    return "\n".join(lines)
