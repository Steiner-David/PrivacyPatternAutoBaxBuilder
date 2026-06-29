import keyword
import re
from pathlib import Path

import agent.templates as templates
from agent.privacy_validation import (
    repair_generated_scenario_metadata,
    validate_public_implementation_text,
    validate_scenario_metadata,
)
from agent.config import args, logger
from agent.utils import AgentException, agentic_loop, generate_with_retries
from models import Conversation, Response
from scenarios import all_scenarios


def scenario_idea_is_novel(scenario: dict) -> bool:
    """Checks if a scenario idea is novel compared to existing ones."""
    existing_scenarios = {
        f.name
        for f in Path(args.path).iterdir()
        if f.is_dir() and f.name != "fewshot_privacy"
    } | {scenario.id for scenario in all_scenarios}

    prompt = templates.scenario_is_novel.format(
        title=scenario["title"],
        description=scenario["description"],
        existing_scenarios=", ".join(existing_scenarios),
    )
    conversation = Conversation().add_message(Response(role="user", text=prompt))
    response = generate_with_retries(
        conversation,
        temperature=0,
        purpose="generate_scenario_ideas: checking if scenario is novel",
    )
    if "yes" in response.text and "no" not in response.text:
        logger.info(f"scenario {scenario['title']} is a duplicate")
        return False
    elif "no" in response.text and "yes" not in response.text:
        logger.info(f"scenario {scenario['title']} is novel")
        return True
    else:
        logger.warning(
            f"inconclusive whether scenario {scenario['title']} is a duplicate"
        )
        return False


def make_identifier(s: str) -> str:
    s = re.sub(r"\W", "_", s)  # \W = anything not a letter, digit, underscore
    if re.match(r"^\d", s):
        s = "_" + s
    if keyword.iskeyword(s):  # python keywords
        s += "_"
    return s


SCENARIO_FIELD_LABELS = {
    "scenario title": "title",
    "scenario description": "description",
    "selected privacypatterns org patterns": "selected_privacy_patterns",
    "selected privacypatterns patterns": "selected_privacy_patterns",
    "selected privacy patterns": "selected_privacy_patterns",
    "selected pattern ids": "selected_privacy_patterns",
    "pseudonymous identity mode": "pseudonymous_identity_mode",
    "personal data involved": "personal_data",
    "personal data": "personal_data",
    "declared purpose": "declared_purpose",
    "allowed data use": "allowed_data_use",
    "forbidden data use": "forbidden_data_use",
    "allowed storage": "allowed_storage",
    "forbidden storage": "forbidden_storage",
    "expected privacy preserving behavior": "expected_privacy_preserving_behavior",
    "expected privacy violating behavior": "expected_privacy_violating_behavior",
    "persistent state": "needs_db",
    "needs secret": "needs_secret",
}


def _normalize_scenario_label(label: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", label.strip().lower()).strip()


def _extract_scenario_block(text: str) -> str | None:
    match = re.search(r"<SCENARIO>\s*(.*?)\s*</SCENARIO>", text, re.DOTALL | re.I)
    if match:
        return match.group(1)
    return None


def _parse_scenario_fields(block: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    current_key: str | None = None
    for line in block.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        field_match = re.match(r"^(?:[-*]\s*)?([^:]+):\s*(.*)$", stripped)
        if field_match:
            label = _normalize_scenario_label(field_match.group(1))
            key = SCENARIO_FIELD_LABELS.get(label)
            if key:
                current_key = key
                fields[current_key] = field_match.group(2).strip()
                continue
        if current_key:
            fields[current_key] = (fields[current_key] + " " + stripped).strip()
    return fields


def _missing_scenario_fields(fields: dict[str, str]) -> list[str]:
    return [
        label
        for label, key in SCENARIO_FIELD_LABELS.items()
        if key not in fields or not fields[key].strip()
    ]


def parse_scenario_idea(conversation: Conversation) -> dict:
    """Parses the scenario idea from the conversation."""
    block = _extract_scenario_block(conversation.responses[-1].text)
    if not block:
        raise AgentException("ParseError", "Could not parse scenario ideas")
    fields = _parse_scenario_fields(block)
    missing = _missing_scenario_fields(fields)
    if missing:
        raise AgentException(
            "ParseError",
            "Could not parse scenario idea field(s): " + ", ".join(missing),
        )

    parsed_scenario = {
        "title": make_identifier("".join(fields["title"].split())),
        "description": fields["description"],
        "selected_privacy_patterns": [
            part.strip().upper()
            for part in re.split(r"[,;\n]+", fields["selected_privacy_patterns"])
            if part.strip()
        ],
        "pseudonymous_identity_mode": fields["pseudonymous_identity_mode"],
        "personal_data": fields["personal_data"],
        "declared_purpose": fields["declared_purpose"],
        "allowed_data_use": fields["allowed_data_use"],
        "forbidden_data_use": fields["forbidden_data_use"],
        "allowed_storage": fields["allowed_storage"],
        "forbidden_storage": fields["forbidden_storage"],
        "expected_privacy_preserving_behavior": fields[
            "expected_privacy_preserving_behavior"
        ],
        "expected_privacy_violating_behavior": fields[
            "expected_privacy_violating_behavior"
        ],
        "needs_db": fields["needs_db"].strip().lower() == "true",
        "needs_secret": fields["needs_secret"].strip().lower() == "true",
    }
    try:
        validate_public_implementation_text(parsed_scenario["title"], "Scenario title")
        validate_public_implementation_text(
            parsed_scenario["description"], "Scenario description"
        )
    except Exception as exc:
        raise AgentException(
            "PublicImplementationOracleLeak",
            str(exc),
        ) from exc
    repair_generated_scenario_metadata(parsed_scenario)
    validate_scenario_metadata(parsed_scenario)
    return parsed_scenario


def generate_scenario_idea() -> dict:
    """Generates a new scenario idea."""
    existing_scenarios = {
        f.name
        for f in Path(args.path).iterdir()
        if f.is_dir() and f.name != "fewshot_privacy"
    } | {scenario.id for scenario in all_scenarios}

    prompt = templates.generate_scenario.format(
        scenario_template=templates.scenario_template,
        privacy_pattern_list=templates.privacy_pattern_list,
        existing_scenarios=", ".join(existing_scenarios),
        endpoints=args.difficulty,
    )

    conversation = Conversation().add_message(Response(role="user", text=prompt))
    response = generate_with_retries(
        conversation,
        temperature=1,
        purpose="generate_scenario_ideas: generating scenario idea",
    )
    conversation.add_message(response)

    return agentic_loop(
        conversation,
        parse_scenario_idea,
        args.N_RETRIES,
        "parsing scenario idea",
        templates.scenario_template,
    )
