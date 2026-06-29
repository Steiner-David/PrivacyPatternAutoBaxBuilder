import re

import agent.templates as templates
from agent.config import args, logger
from agent.privacy_validation import format_scenario_metadata_for_prompt
from agent.utils import AgentException, agentic_loop, generate_with_retries
from models import Conversation, Response
from privacy_patterns import get_privacy_pattern_by_id


def parse_privacy_probe_strategy(conversation: Conversation) -> str:
    """Parse the privacy probe strategy from the conversation."""
    pattern = r"<STRATEGY>(.*?)</STRATEGY>"
    match = re.search(pattern, conversation.responses[-1].text, re.DOTALL)

    if match:
        return f"<STRATEGY>\n{match.group(1).strip()}\n</STRATEGY>"
    if "DISCARD" in conversation.responses[-1].text:
        return ""
    raise AgentException("ParseError", "Could not parse privacy probe strategy")


def generate_privacy_probe_strategy(
    pattern_id: str,
    pattern_reasons: str,
    scenario: dict,
    conversation: Conversation,
) -> str:
    """Generate a privacy probe strategy for a PrivacyPatterns.org pattern."""
    pattern = get_privacy_pattern_by_id(pattern_id)
    logger.info("generating privacy probe strategy for %s", pattern_id)

    prompt = templates.generate_privacy_probe_strategy.format(
        scenario_title=scenario["title"],
        scenario_description=scenario["description"],
        scenario_privacy_metadata=format_scenario_metadata_for_prompt(scenario),
        scenario_openapi=scenario["schema"],
        pattern_id=pattern.value["id"],
        pattern_name=pattern.value["name"],
        pattern_source_url=pattern.value["source_url"],
        pattern_meaning=pattern.value["benchmark_meaning"],
        pattern_probe_guidance=pattern.value["probe_guidance"],
        pattern_reasons=pattern_reasons,
        privacy_tool_signatures=templates.privacy_tool_signatures,
        format_specifications=templates.privacy_probe_strategy_format,
    )

    conversation.add_message(Response(role="user", text=prompt))
    response = generate_with_retries(
        conversation,
        temperature=0,
        purpose=f"generate_privacy_probe_strategies: {pattern_id}",
    )
    conversation.add_message(response)

    return agentic_loop(
        conversation,
        parse_privacy_probe_strategy,
        args.N_RETRIES,
        "parsing privacy probe strategy",
        templates.privacy_probe_strategy_format,
    )


def compliance_privacy_probe_strategy(
    privacy_probe_strategy: str, scenario: dict, conversation: Conversation
) -> str:
    """Ensure the privacy probe strategy is grounded in the scenario."""
    if not privacy_probe_strategy:
        return privacy_probe_strategy

    logger.info("ensuring compliance of privacy probe strategy")

    prompt = templates.compliance_privacy_probe_strategy.format(
        scenario_privacy_metadata=format_scenario_metadata_for_prompt(scenario),
        scenario_text_spec=scenario["text_spec"],
        format_specifications=templates.privacy_probe_strategy_format,
    )

    conversation.add_message(Response(role="user", text=prompt))
    response = generate_with_retries(
        conversation,
        temperature=0,
        purpose="generate_privacy_probe_strategies: compliance pass",
    )
    conversation.add_message(response)

    return agentic_loop(
        conversation,
        parse_privacy_probe_strategy,
        args.N_RETRIES,
        "parsing privacy probe strategy",
        templates.privacy_probe_strategy_format,
    )
