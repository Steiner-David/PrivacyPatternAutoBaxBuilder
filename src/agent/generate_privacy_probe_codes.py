import ast
import re

import agent.templates as templates
from agent.config import args, logger
from agent.generated_imports import (
    ensure_generated_test_runtime_imports,
    ensure_import_line,
)
from agent.privacy_validation import (
    PrivacyValidationError,
    validate_aggregation_gateway_probe_code,
    validate_location_granularity_probe_code,
    validate_privacy_probe_helper_usage,
    validate_pseudonymous_identity_probe_code,
    validate_selective_access_control_probe_code,
    validate_strip_invisible_metadata_probe_code,
    validate_test_metadata_consistency,
)
from agent.utils import AgentException, agentic_loop, clean_code, generate_with_retries
from models import Conversation, Response
from privacy_patterns import all_privacy_pattern_ids, get_privacy_pattern_by_id


def parse_privacy_probe_code(
    conversation: Conversation, header: bool = True
) -> tuple[str, str] | str:
    """Parse privacy probe code from the model response."""
    raw_text = conversation.responses[-1].text

    if "DISCARD" in raw_text and len(raw_text) < 100:
        if header:
            return "", ""
        return ""

    if header:
        header_match = re.search(
            r"<HEADER>\s*```(?:python\s*)?(.*?)```\s*</HEADER>", raw_text, re.DOTALL
        )
    function_match = re.search(
        r"<FUNCTION>\s*```(?:python\s*)?(.*?)```\s*</FUNCTION>", raw_text, re.DOTALL
    )

    if header and not header_match:
        raise AgentException("ParseError", "Could not parse HEADER section.")
    if not function_match:
        raise AgentException("ParseError", "Could not parse FUNCTION section.")

    header_code = ""
    if header and header_match:
        header_code = header_match.group(1).strip()
    function_code = function_match.group(1).strip()

    syntax_errors = []
    if header:
        try:
            compile(header_code, "<string>", "exec")
        except SyntaxError as e:
            syntax_errors.append(f"Unable to compile header, SyntaxError: {e}")

    try:
        compile(function_code, "<string>", "exec")
    except SyntaxError as e:
        syntax_errors.append(
            f"Unable to compile privacy probe function, SyntaxError: {e}"
        )

    if syntax_errors:
        raise AgentException(
            f"{len(syntax_errors)} SyntaxError(s) found in the code:\n\n",
            "\n\n".join(syntax_errors),
        )

    if header:
        return header_code, function_code
    return function_code


def _privacy_probe_function_name(function_code: str) -> str | None:
    match = re.search(r"def\s+(\w+)\s*\(", function_code)
    if not match:
        return None
    return match.group(1)


def _is_empty_set_constructor(node: ast.AST | None) -> bool:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "set"
        and not node.args
        and not node.keywords
    )


def _empty_set_return_contract_present(function_code: str) -> bool:
    """Accept literal `return set()` and common accumulator-return probes."""
    try:
        tree = ast.parse(function_code)
    except SyntaxError:
        return False

    functions = [node for node in tree.body if isinstance(node, ast.FunctionDef)]
    for function in functions:
        empty_set_names: set[str] = set()
        for node in ast.walk(function):
            if isinstance(node, ast.Assign) and _is_empty_set_constructor(node.value):
                empty_set_names.update(
                    target.id for target in node.targets if isinstance(target, ast.Name)
                )
            elif (
                isinstance(node, ast.AnnAssign)
                and isinstance(node.target, ast.Name)
                and _is_empty_set_constructor(node.value)
            ):
                empty_set_names.add(node.target.id)

        for node in ast.walk(function):
            if not isinstance(node, ast.Return):
                continue
            if _is_empty_set_constructor(node.value):
                return True
            if isinstance(node.value, ast.Name) and node.value.id in empty_set_names:
                return True
    return False


def validate_privacy_probe_code_for_pattern(
    function_code: str,
    expected_pattern_id: str,
    expected_function_name: str | None = None,
    scenario: dict | None = None,
) -> None:
    """Ensure a generated probe uses exactly the expected PrivacyPattern enum."""
    if expected_function_name is not None:
        actual_function_name = _privacy_probe_function_name(function_code)
        if actual_function_name != expected_function_name:
            raise AgentException(
                "PrivacyProbeNameError",
                "Privacy probe function name must be "
                + expected_function_name
                + ", got "
                + str(actual_function_name)
                + ". Keep the exact requested function signature.",
            )

    allowed = set(all_privacy_pattern_ids())
    references = set(re.findall(r"PrivacyPattern\.([A-Z_]+)", function_code))
    unknown = references - allowed
    if unknown:
        raise AgentException(
            "PrivacyPatternError",
            "Privacy probe references unsupported PrivacyPattern enum value(s): "
            + ", ".join(sorted(unknown))
            + ". Only use PrivacyPattern."
            + expected_pattern_id
            + " for this probe.",
        )
    if expected_pattern_id not in references:
        raise AgentException(
            "PrivacyPatternError",
            "Privacy probe must return {PrivacyPattern."
            + expected_pattern_id
            + "} when it detects a violation.",
        )
    unexpected = references - {expected_pattern_id}
    if unexpected:
        raise AgentException(
            "PrivacyPatternError",
            "Privacy probe for "
            + expected_pattern_id
            + " must not reference other selected patterns: "
            + ", ".join(sorted(unexpected)),
        )
    if not _empty_set_return_contract_present(function_code):
        raise AgentException(
            "ReturnContractError",
            "Privacy probe must return set() when no violation is detected, or "
            "return an accumulator initialized with set().",
        )
    if expected_pattern_id == "AGGREGATION_GATEWAY":
        try:
            validate_aggregation_gateway_probe_code([function_code])
        except PrivacyValidationError as exc:
            raise AgentException("AggregationGatewayProbeError", str(exc)) from exc
    if expected_pattern_id == "LOCATION_GRANULARITY":
        try:
            validate_location_granularity_probe_code([function_code])
        except PrivacyValidationError as exc:
            raise AgentException("LocationGranularityProbeError", str(exc)) from exc
    if expected_pattern_id == "PSEUDONYMOUS_IDENTITY":
        try:
            validate_pseudonymous_identity_probe_code(
                [function_code], scenario=scenario
            )
        except PrivacyValidationError as exc:
            raise AgentException("PseudonymousIdentityProbeError", str(exc)) from exc
    if expected_pattern_id == "STRIP_INVISIBLE_METADATA":
        try:
            validate_strip_invisible_metadata_probe_code([function_code])
        except PrivacyValidationError as exc:
            raise AgentException("StripInvisibleMetadataProbeError", str(exc)) from exc
    if expected_pattern_id == "SELECTIVE_ACCESS_CONTROL":
        try:
            validate_selective_access_control_probe_code([function_code])
        except PrivacyValidationError as exc:
            raise AgentException("SelectiveAccessControlProbeError", str(exc)) from exc


def parse_privacy_probe_code_for_pattern(
    conversation: Conversation,
    expected_pattern_id: str,
    header: bool = True,
    expected_function_name: str | None = None,
    scenario: dict | None = None,
) -> tuple[str, str] | str:
    parsed = parse_privacy_probe_code(conversation, header=header)
    if header:
        probe_header_code, probe_test_code = parsed
        if not probe_header_code and not probe_test_code:
            return parsed
        try:
            validate_privacy_probe_helper_usage([probe_header_code, probe_test_code])
        except PrivacyValidationError as exc:
            raise AgentException("PrivacyProbeHelperUsageError", str(exc)) from exc
        validate_privacy_probe_code_for_pattern(
            probe_test_code,
            expected_pattern_id,
            expected_function_name,
            scenario=scenario,
        )
        return parsed
    if not parsed:
        return parsed
    try:
        validate_privacy_probe_helper_usage([parsed])
    except PrivacyValidationError as exc:
        raise AgentException("PrivacyProbeHelperUsageError", str(exc)) from exc
    validate_privacy_probe_code_for_pattern(
        parsed,
        expected_pattern_id,
        expected_function_name,
        scenario=scenario,
    )
    return parsed


def augment_header_privacy_probe_signatures(
    header_code: str, probe_header_code: str, probe_test_code: str
) -> str:
    """Augment generated probe headers with helper imports."""
    helper_names = [
        "FileNotFoundInContainer",
        "SQLQueryExecError",
        "place_file_on_docker",
        "load_file_from_docker",
        "discover_files_in_docker",
        "execute_sql_on_docker",
        "download_db_from_docker",
        "test_sqlite_db_created",
        "sqlite_contains_value",
        "sqlite_contains_any_value",
        "sqlite_contains_column_like",
        "sqlite_aggregation_gateway_has_raw_records",
        "sqlite_location_granularity_has_precise_location",
        "sqlite_metadata_contains_forbidden_values",
        "response_contains_forbidden_fields",
        "response_contains_forbidden_values",
        "response_exposes_forbidden_resource",
        "metadata_contains_forbidden_values",
        "docker_files_contain_forbidden_metadata",
        "make_png_with_invisible_metadata",
        "container_logs_contain_values",
        "docker_container_logs_contain_values",
        "pseudonym_derives_from_identifier",
        "normalize_json_for_search",
    ]

    if (
        "SCENARIO_FILE_PATH" in probe_header_code
        or "SCENARIO_FILE_PATH" in probe_test_code
    ):
        if "SCENARIO_FILE_PATH" not in header_code:
            header_code = ensure_import_line(
                header_code, "from scenario_files import SCENARIO_FILE_PATH"
            )

    missing_helpers = [
        helper
        for helper in helper_names
        if (helper in probe_header_code or helper in probe_test_code)
        and helper not in header_code
    ]
    if missing_helpers:
        header_code = ensure_import_line(
            header_code,
            "from privacy_probes import "
            + ", ".join(missing_helpers)
        )

    if "PrivacyPattern" in probe_test_code and "PrivacyPattern" not in header_code:
        header_code = ensure_import_line(
            header_code, "from privacy_patterns import PrivacyPattern"
        )

    return ensure_generated_test_runtime_imports(
        header_code, probe_header_code, probe_test_code
    )


def generate_privacy_probe_code(
    pattern_id: str, scenario: dict, conversation: Conversation
) -> None:
    """Generate privacy probe code for the given PrivacyPatterns.org pattern."""
    pattern = get_privacy_pattern_by_id(pattern_id)
    logger.info("generating privacy probe code for %s", pattern_id)

    func_name = f"priv_test_{pattern.value['id'].lower()}"
    privacy_code_format = templates.privacy_code_format.format(
        pattern_id=pattern.value["id"],
        func_name=func_name,
    )
    prompt = templates.generate_privacy_probe_code.format(
        header_code=scenario["header_code"],
        privacy_tool_signatures=templates.privacy_tool_signatures,
        pattern_id=pattern.value["id"],
        format_specifications=privacy_code_format,
    )

    conversation.add_message(Response(role="user", text=prompt))
    response = generate_with_retries(
        conversation,
        temperature=0,
        purpose=f"generate_privacy_probe_codes: {pattern_id}",
    )
    conversation.add_message(response)

    probe_header_code, probe_test_code = agentic_loop(
        conversation,
        lambda c: parse_privacy_probe_code_for_pattern(
            c,
            pattern.value["id"],
            header=True,
            expected_function_name=func_name,
            scenario=scenario,
        ),
        args.N_RETRIES,
        "parsing privacy probe code",
        privacy_code_format,
    )

    if not probe_header_code and not probe_test_code:
        logger.info("Discarding privacy probe")
        return

    scenario["header_code"] = augment_header_privacy_probe_signatures(
        scenario["header_code"], probe_header_code, probe_test_code
    )
    scenario["header_code"] += "\n\n" + probe_header_code
    scenario["header_code"] = clean_code(scenario["header_code"])

    scenario["privacy_tests_code"].append(probe_test_code)
    scenario["privacy_tests_names"].append(func_name)
    scenario["all_tests_names"].append(func_name)
    validate_test_metadata_consistency(scenario)
