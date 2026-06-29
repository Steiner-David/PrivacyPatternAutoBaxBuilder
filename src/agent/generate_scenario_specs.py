import re

import yaml
from openapi_spec_validator import validate

import agent.templates as templates
from agent.config import args
from agent.privacy_validation import (
    public_implementation_description,
    public_implementation_title,
    repair_generated_scenario_metadata,
    validate_public_implementation_text,
    validate_scenario_metadata,
)
from agent.utils import AgentException, agentic_loop, generate_with_retries
from models import Conversation, Response


def extract_yaml(schema_text: str) -> str:
    """Extracts YAML content from a schema text block."""
    match = re.search(
        r"<SCHEMA>\s*```(?:ya?ml\s*)?(.*?)```\s*</SCHEMA>",
        schema_text,
        re.DOTALL | re.IGNORECASE,
    )
    if match:
        return match.group(1).strip()
    raise AgentException(
        "FormatError",
        "failed to parse the OpenAPI schema, adhere to the required format.",
    )


def validate_openapi(conversation: Conversation, scenario: dict | None = None) -> str:
    """Validates the OpenAPI schema from the conversation."""
    if (schema := extract_yaml(conversation.responses[-1].text)) is not None:
        spec_dict = yaml.safe_load(schema)
        validate(spec_dict)
        if scenario is not None:
            candidate = dict(scenario)
            candidate["schema"] = schema
            validate_public_implementation_text(schema, "OpenAPI schema")
            repair_generated_scenario_metadata(candidate)
            validate_scenario_metadata(candidate)
            scenario.update(
                {
                    key: candidate[key]
                    for key in [
                        "selected_privacy_patterns",
                        "pseudonymous_identity_mode",
                        "allowed_storage",
                        "forbidden_storage",
                    ]
                    if key in candidate
                }
            )
        return schema
    else:  # format error
        raise AgentException(
            "FormatError", "failed to parse the OpenAPI, adhere to the required format."
        )


def generate_openapi(scenario: dict) -> str:
    """Generates an OpenAPI schema for the given scenario."""
    public_title = public_implementation_title(scenario)
    public_description = public_implementation_description(scenario)
    scenario_spec = templates.public_scenario_spec.format(
        title=public_title,
        description=public_description,
        needs_db=scenario["needs_db"],
        needs_secret=scenario["needs_secret"],
    )

    prompt = templates.generate_openapi.format(
        scenario_template=templates.public_scenario_template,
        example_spec=templates.example_spec,
        example_openapi=templates.example_openapi,
        scenario_spec=scenario_spec,
    )

    conversation = Conversation().add_message(Response(role="user", text=prompt))
    response = generate_with_retries(
        conversation,
        temperature=0,
        purpose="generate_scenario_specs: generating OpenAPI schema",
    )
    conversation.add_message(response)

    return agentic_loop(
        conversation,
        lambda c: validate_openapi(c, scenario),
        args.N_RETRIES,
        "validating the OpenAPI schema",
        templates.schema_format,
    )


def parse_text_spec(
    conversation: Conversation, scenario: dict | None = None
) -> str:
    """Parses the textual specification from the conversation."""
    match = re.search(
        r"<TEXT>\s*(.*?)\s*</TEXT>", conversation.responses[-1].text, re.DOTALL
    )
    if match:
        text_spec = match.group(1).strip()
        if scenario is not None:
            candidate = dict(scenario)
            candidate["text_spec"] = text_spec
            validate_public_implementation_text(text_spec, "Text specification")
            repair_generated_scenario_metadata(candidate)
            validate_scenario_metadata(candidate)
            scenario.update(
                {
                    key: candidate[key]
                    for key in [
                        "selected_privacy_patterns",
                        "pseudonymous_identity_mode",
                        "allowed_storage",
                        "forbidden_storage",
                    ]
                    if key in candidate
                }
            )
        return text_spec
    raise AgentException(
        "FormatError", "failed to parse the text spec, adhere to the required format."
    )


def generate_text_spec(scenario: dict) -> str:
    """Generates a textual specification for the given scenario."""
    public_title = public_implementation_title(scenario)
    public_description = public_implementation_description(scenario)
    prompt = templates.generate_text_spec.format(
        scenario_template_with_openapi=templates.public_scenario_template,
        example_title=templates.example_title,
        example_description=templates.example_description,
        example_openapi=templates.example_openapi,
        example_text_spec=templates.example_text_spec,
        scenario_title=public_title,
        scenario_description=public_description,
        scenario_openapi=scenario["schema"],
    )

    conversation = Conversation().add_message(Response(role="user", text=prompt))
    response = generate_with_retries(
        conversation,
        temperature=0,
        purpose="generate_scenario_specs: generating textual specification",
    )
    conversation.add_message(response)

    return agentic_loop(
        conversation,
        lambda c: parse_text_spec(c, scenario),
        args.N_RETRIES,
        "parsing the textual specification",
        templates.text_spec_format,
    )
