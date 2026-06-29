import re

import agent.templates as templates
from agent.config import args, logger
from agent.privacy_validation import (
    format_scenario_metadata_for_prompt,
    public_implementation_description,
    public_implementation_title,
    sanitize_functional_test_specs,
    validate_functional_tests_are_not_privacy_probes,
)
from agent.utils import AgentException, agentic_loop, generate_with_retries
from models import Conversation, Response


def parse_tests_spec(
    conversation: Conversation, scenario: dict | None = None
) -> list[str]:
    """Parses functional test specifications from the conversation."""
    raw_tests_spec = conversation.responses[-1].text
    pattern = r"<TEST>(.*?)</TEST>"
    tests = [test.strip() for test in re.findall(pattern, raw_tests_spec, re.DOTALL)]

    if raw_tests_spec.count("<TEST>") != raw_tests_spec.count("</TEST>"):
        raise AgentException("ParseError", "Mismatch of <TEST>'s and </TEST>'s")

    if raw_tests_spec.count("<TEST>") != len(tests):
        raise AgentException(
            "ParseError",
            f"Generated {raw_tests_spec.count('<TEST>')} tests but could only parse len(tests) of them.",
        )
    original_count = len(tests)
    tests = sanitize_functional_test_specs(tests, scenario)
    if not tests:
        raise AgentException(
            "FunctionalPrivacySeparationError",
            "All generated functional test specifications were privacy probes. "
            "Regenerate tests that check only normal API behavior such as accepted "
            "submissions, required response fields, invalid 4xx inputs, and numeric "
            "aggregate calculations.",
        )
    if len(tests) < original_count:
        logger.info(
            "Dropped %s privacy-only functional test specification(s)",
            original_count - len(tests),
        )
    validate_functional_tests_are_not_privacy_probes(tests)
    return tests


def generate_tests_spec(scenario: dict, conversation: Conversation) -> list[str]:
    """Generates functional test specifications for the scenario."""
    public_title = public_implementation_title(scenario)
    public_description = public_implementation_description(scenario)
    prompt = templates.functional_tests_specs.format(
        test_spec_template=templates.test_spec_template,
        example_title=templates.example_title,
        example_description=templates.example_description,
        example_openapi=templates.example_openapi,
        example_tests_spec=templates.example_tests_spec,
        scenario_title=public_title,
        scenario_description=public_description,
        scenario_privacy_metadata=format_scenario_metadata_for_prompt(scenario),
        scenario_openapi=scenario["schema"],
    )

    conversation.add_message(Response(role="user", text=prompt))
    response = generate_with_retries(
        conversation,
        temperature=0,
        purpose="generate_functional_tests: generating functional test specifications",
    )
    conversation.add_message(response)

    logger.info(
        f"Generated {response.text.count('<TEST>')} functional tests for scenario {scenario['title']}"
    )

    tests = agentic_loop(
        conversation,
        lambda c: parse_tests_spec(c, scenario),
        args.N_RETRIES,
        f"parsing functional test specifications for scenario {scenario['title']}",
        templates.test_spec_template,
    )
    validate_functional_tests_are_not_privacy_probes(tests)
    sanitized_response = "<TESTS>\n" + "\n\n".join(
        f"<TEST>\n{test}\n</TEST>" for test in tests
    ) + "\n</TESTS>"
    if conversation.responses:
        conversation.responses = [
            conversation.responses[0],
            Response(role="assistant", text=sanitized_response),
        ]
    return tests


def parse_tests_code(
    conversation: Conversation, scenario: dict
) -> tuple[str, list[str], list[str]]:
    """Parses functional test code from the conversation."""
    raw_tests_code = conversation.responses[-1].text
    header_match = re.search(
        r"<HEADER>\s*```(?:python\s*)?(.*?)```\s*</HEADER>", raw_tests_code, re.DOTALL
    )
    function_matches = re.findall(
        r"<FUNCTION>\s*```(?:python\s*)?(.*?)```\s*</FUNCTION>",
        raw_tests_code,
        re.DOTALL,
    )

    if not header_match:
        raise AgentException(
            "ParseError",
            "Could not parse HEADER section.",
        )

    header_code = header_match.group(1).strip()

    if not function_matches:
        raise AgentException(
            "ParseError",
            "Could not parse FUNCTION sections.",
        )

    function_codes = [func.strip() for func in function_matches]

    # mismatch in functional test code snippets and number of tests in the spec
    if len(function_codes) != len(scenario["tests_spec"]):
        raise AgentException(
            "ConsistencyError",
            f"Generated specs for {len(scenario['tests_spec'])} testcases, yet parsed {len(function_codes)} corresponding code snippets. The python function for each testcase in the specification should be wrapped in one <FUNCTION> section.",
        )

    function_names = []
    for i, code in enumerate(function_codes, start=1):
        match = re.search(r"def\s+(\w+)\s*\(", code)
        if not match:
            raise AgentException(
                "ParseError",
                f"Not able to find a function definition in <FUNCTION> block {i}",
            )
        function_names.append(match.group(1))

    # check if code is compilable
    syntax_errors = []
    for i, code_block in enumerate([header_code, *function_codes]):
        try:
            compile(code_block, "<string>", "exec")
        except SyntaxError as e:
            if i == 0:
                syntax_errors.append(f"Unable to compile header, SyntaxError: {e}")
            else:
                syntax_errors.append(
                    f"Unable to compile {function_names[i-1]}, SyntaxError: {e}"
                )

    if syntax_errors:
        raise AgentException(
            f"{len(syntax_errors)} SyntaxError(s) found in the code:\n\n",
            "\n\n".join(syntax_errors),
        )
    validate_functional_tests_are_not_privacy_probes(function_codes)

    return header_code, function_codes, function_names


def generate_tests_code(
    scenario: dict, conversation: Conversation
) -> tuple[str, list[str], list[str]]:
    """Generates Python code for the functional tests."""
    # scnenario_tests_spec_combined = (
    #     "<TESTS>\n<TEST>\n"
    #     + "\n</TEST>\n\n<TEST>\n".join(scenario["tests_spec"])
    #     + "\n</TEST>\n</TESTS>"
    # )
    scenario_tests_spec_combined = (
        "<TESTS>\n"
        + "\n\n".join(f"<TEST>\n{test}\n</TEST>" for test in scenario["tests_spec"])
        + "\n</TESTS>"
    )
    prompt = templates.functional_tests_code.format(
        func_tool_signatures=templates.func_tool_signatures,
        scenario_tests_spec=scenario_tests_spec_combined,
        tests_code_template=templates.tests_code_template,
        example_tests_code=templates.example_tests_code,
    )

    conversation.add_message(Response(role="user", text=prompt))
    response = generate_with_retries(
        conversation,
        temperature=0,
        purpose="generate_functional_tests: generating functional tests code",
    )
    conversation.add_message(response)

    logger.info("Generated functional tests code")

    # parse, verify consistency and check if compiles
    header_code, function_codes, function_names = agentic_loop(
        conversation,
        lambda c: parse_tests_code(c, scenario),
        args.N_RETRIES,
        "parsing, verifying consistency and compilability of the functional tests code",
        templates.tests_code_template,
    )

    # augment header code
    FUNCTEST_SIGNATURES = [
        "place_file_on_docker",
    ]

    if any(
        (signature in header_code or signature in function_codes)
        for signature in FUNCTEST_SIGNATURES
    ):
        header_code = (
            "from privacy_probes import "
            + ", ".join(
                signature
                for signature in FUNCTEST_SIGNATURES
                if (signature in header_code or signature in function_codes)
            )
            + "\n"
            + header_code
        )

    return header_code, function_codes, function_names
