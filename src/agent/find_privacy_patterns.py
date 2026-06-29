import posixpath

import agent.templates as templates
from agent.config import args, logger
from agent.privacy_validation import (
    filter_patterns_to_scenario_selection,
    format_scenario_metadata_for_prompt,
)
from agent.utils import generate_with_retries
from models import Conversation, Response
from privacy_patterns import all_privacy_pattern_ids

REJECTED_GENERIC_LABELS = {
    "DATA_MINIMIZATION",
    "RIGHT_TO_ERASURE",
    "RETENTION_LIMITATION",
    "PURPOSE_LIMITATION",
    "CONSENT_WITHDRAWAL",
}


def parse_privacy_patterns(text: str) -> dict[str, str]:
    """Parse PrivacyPatterns.org pattern IDs from model output."""
    allowed_ids = set(all_privacy_pattern_ids())
    findings: dict[str, str] = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        pattern_id, reason = line.split(":", 1)
        pattern_id = pattern_id.strip().upper().replace("-", "_").replace(" ", "_")
        if pattern_id in REJECTED_GENERIC_LABELS:
            if args.debug:
                logger.warning("Rejected generic privacy label %s", pattern_id)
            continue
        if pattern_id not in allowed_ids:
            if args.debug and pattern_id:
                logger.warning("Rejected unknown PrivacyPatterns.org ID %s", pattern_id)
            continue
        findings[pattern_id] = f"{pattern_id}: {reason.strip()}"
    return findings


def find_privacy_patterns_in_code(
    scenario: dict, implementation: dict, conversation: Conversation
) -> dict[str, str]:
    """Find PrivacyPatterns.org patterns relevant to the implementation code."""
    prompt = templates.find_privacy_patterns_in_code.format(
        privacy_pattern_list=templates.privacy_pattern_list,
        scenario_title=scenario["title"],
        scenario_description=scenario["description"],
        scenario_privacy_metadata=format_scenario_metadata_for_prompt(scenario),
        scenario_openapi=scenario["schema"],
        implementation="\n\n".join(
            [
                f"File {posixpath.basename(path)}:\n```\n{content.strip()}\n```\n"
                for path, content in implementation.items()
            ]
        ),
    )

    conversation.add_message(Response(role="user", text=prompt))
    response = generate_with_retries(
        conversation,
        temperature=0,
        purpose="find_privacy_patterns: finding patterns in code",
    )
    conversation.add_message(response)

    if args.debug:
        logger.info(response.text)

    found_patterns = filter_patterns_to_scenario_selection(
        scenario, parse_privacy_patterns(response.text)
    )
    logger.info("found privacy pattern(s): %s", ", ".join(found_patterns.keys()))
    return found_patterns


def find_privacy_patterns_in_scenario(
    scenario: dict, conversation: Conversation
) -> dict[str, str]:
    """Find PrivacyPatterns.org patterns relevant to the scenario description."""
    prompt = templates.find_privacy_patterns_in_scenario.format(
        privacy_pattern_list=templates.privacy_pattern_list,
        scenario_title=scenario["title"],
        scenario_description=scenario["description"],
        scenario_privacy_metadata=format_scenario_metadata_for_prompt(scenario),
        scenario_openapi=scenario["schema"],
    )

    conversation.add_message(Response(role="user", text=prompt))
    response = generate_with_retries(
        conversation,
        temperature=0,
        purpose="find_privacy_patterns: finding patterns in scenario",
    )
    conversation.add_message(response)

    if args.debug:
        logger.info(response.text)

    found_patterns = filter_patterns_to_scenario_selection(
        scenario, parse_privacy_patterns(response.text)
    )
    logger.info("found privacy pattern(s): %s", ", ".join(found_patterns.keys()))
    return found_patterns
