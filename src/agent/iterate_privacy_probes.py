import posixpath
import re

import agent.templates as templates
from agent.config import args, logger
from agent.generate_privacy_probe_codes import (
    augment_header_privacy_probe_signatures,
    parse_privacy_probe_code_for_pattern,
)
from agent.iterate_functional_tests import parse_implementation
from agent.privacy_validation import (
    format_scenario_metadata_for_prompt,
    record_privacy_probe_validation_evidence,
)
from agent.utils import (
    AgentException,
    agentic_loop,
    clean_code,
    generate_with_retries,
    record_verdict,
    save_code,
)
from models import Conversation, Response
from privacy_patterns import get_privacy_pattern_by_id


def parse_verdict(conversation: Conversation) -> int:
    """Parse a 1/2 verdict from the conversation."""
    verdict = re.search(
        r"<VERDICT>\s*(\d+)\s*</VERDICT>", conversation.responses[-1].text
    )
    if verdict:
        if verdict.group(1) not in ["1", "2"]:
            raise AgentException("ParseError", "Invalid verdict")
        return int(verdict.group(1))
    raise AgentException("ParseError", "Could not parse verdict from response")


def _pattern_for_probe(scenario: dict, i: int):
    privacy_test_name = scenario["privacy_tests_names"][i]
    pattern_id = privacy_test_name.removeprefix("priv_test_").upper()
    return get_privacy_pattern_by_id(pattern_id)


def iterate_compliant_violating(
    scenario: dict,
    i: int,
    implementation: dict,
    test_result: dict,
    conversation: Conversation,
    compliant: bool = True,
) -> int:
    """Judge whether a privacy probe result is correct for an implementation."""
    pattern = _pattern_for_probe(scenario, i)
    privacy_pattern = f"{pattern.value['id']}: {pattern.value['name']}"

    prompt_template = templates.iterate_compliant if compliant else templates.iterate_violating
    prompt = prompt_template.format(
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
        privacy_test_name=scenario["privacy_tests_names"][i],
        privacy_pattern=privacy_pattern,
        header_code=scenario["header_code"],
        privacy_code=scenario["privacy_tests_code"][i],
        test_logs=test_result["test_logs"],
        container_logs=test_result["container_logs"],
    )

    conversation.add_message(Response(role="user", text=prompt))
    response = generate_with_retries(
        conversation,
        temperature=0,
        purpose=f"iterate_privacy_probes: iterating {pattern.value['id']}",
    )
    conversation.add_message(response)

    return agentic_loop(
        conversation,
        parse_verdict,
        args.N_RETRIES,
        "parsing verdict",
        "Respond with 1 or 2, wrapped in <VERDICT> tags.",
    )


def flip_impl(
    make_violating: bool,
    scenario: dict,
    i: int,
    implementation: dict,
    framework: list[str],
) -> dict:
    """Modify the implementation to be privacy-violating or privacy-compliant."""
    pattern = _pattern_for_probe(scenario, i)
    privacy_pattern = f"{pattern.value['id']} - {pattern.value['name']}"

    impl_format = templates.flip_impl_format.format(
        format_specifications="\n\n".join(
            [
                f"<{posixpath.basename(path)}>\n```\n```\n</{posixpath.basename(path)}>\n"
                for path in implementation.keys()
            ]
        )
    )

    if make_violating:
        logger.info("Flipping implementation to be privacy-violating.")
        prompt = templates.flip_impl_privacy_violating.format(
            framework=framework,
            privacy_pattern=privacy_pattern,
            scenario_title=scenario["title"],
            scenario_description=scenario["description"],
            scenario_privacy_metadata=format_scenario_metadata_for_prompt(scenario),
            scenario_openapi=scenario["schema"],
            format_specifications=impl_format,
            implementation="\n\n".join(
                [
                    f"File {posixpath.basename(path)}:\n```\n{content.strip()}\n```\n"
                    for path, content in implementation.items()
                ]
            ),
        )
    else:
        logger.info("Flipping implementation to be privacy-compliant.")
        prompt = templates.flip_impl_privacy_compliant.format(
            framework=framework,
            privacy_pattern=privacy_pattern,
            scenario_title=scenario["title"],
            scenario_description=scenario["description"],
            scenario_privacy_metadata=format_scenario_metadata_for_prompt(scenario),
            scenario_openapi=scenario["schema"],
            format_specifications=impl_format,
            implementation="\n\n".join(
                [
                    f"File {posixpath.basename(path)}:\n```\n{content.strip()}\n```\n"
                    for path, content in implementation.items()
                ]
            ),
        )

    conversation = Conversation().add_message(Response(role="user", text=prompt))
    response = generate_with_retries(
        conversation,
        temperature=0,
        purpose=f"iterate_privacy_probes: flipping implementation for {pattern.value['id']}",
    )
    conversation.add_message(response)

    return agentic_loop(
        conversation,
        lambda c: parse_implementation(c, implementation),
        args.N_RETRIES,
        "parsing re-implementation",
        impl_format,
    )


def fix_privacy_probe(
    conversation: Conversation,
    scenario: dict,
    i: int,
    implementation: dict | None = None,
    test_result: dict | None = None,
) -> str:
    """Fix privacy probe code based on the conversation."""
    pattern = _pattern_for_probe(scenario, i)
    fix_format = templates.fix_privacy_probe_code_format.format(
        privacy_test_name=scenario["privacy_tests_names"][i],
        pattern_id=pattern.value["id"],
    )
    implementation_text = ""
    if implementation:
        implementation_text = "\n\n".join(
            [
                f"File {posixpath.basename(path)}:\n```\n{content.strip()}\n```\n"
                for path, content in implementation.items()
            ]
        )
    test_logs = ""
    container_logs = ""
    if test_result:
        test_logs = test_result.get("test_logs", "")
        container_logs = test_result.get("container_logs", "")
    prompt = templates.fix_privacy_probe_code.format(
        scenario_title=scenario["title"],
        scenario_description=scenario["description"],
        scenario_instructions=format_scenario_metadata_for_prompt(scenario),
        scenario_openapi=scenario["schema"],
        implementation=implementation_text or "No implementation context provided.",
        header_code=scenario["header_code"],
        privacy_test_name=scenario["privacy_tests_names"][i],
        privacy_code=scenario["privacy_tests_code"][i],
        test_logs=test_logs or "No test logs were captured.",
        container_logs=container_logs or "No container logs were captured.",
        privacy_tool_signatures=templates.privacy_tool_signatures,
        pattern_id=pattern.value["id"],
        pattern_name=pattern.value["name"],
        pattern_source_url=pattern.value["source_url"],
        pattern_meaning=pattern.value["benchmark_meaning"],
        format_specifications=fix_format,
    )

    conversation.add_message(Response(role="user", text=prompt))
    response = generate_with_retries(
        conversation,
        temperature=0,
        purpose=f"iterate_privacy_probes: fixing {scenario['privacy_tests_names'][i]}",
    )
    conversation.add_message(response)

    privacy_test_code = agentic_loop(
        conversation,
        lambda c: parse_privacy_probe_code_for_pattern(
            c,
            pattern.value["id"],
            header=False,
            expected_function_name=scenario["privacy_tests_names"][i],
            scenario=scenario,
        ),
        args.N_RETRIES,
        "processing fixed privacy probe",
        fix_format,
    )

    scenario["header_code"] = clean_code(
        augment_header_privacy_probe_signatures(
            scenario["header_code"], "", privacy_test_code
        )
    )
    return privacy_test_code


def iteration_privacy_probe(
    scenario: dict,
    i: int,
    privacy_test: str,
    test_results: dict,
    implementations: dict,
    flags: dict,
    task_dict: dict,
    key: str,
) -> bool:
    """Run one privacy-probe improvement iteration.

    Returns True when the probe should be discarded.
    """
    test_result = test_results[key]
    conversation = Conversation()
    verdict = 0
    if test_result["status"] == "passed":
        try:
            verdict = iterate_compliant_violating(
                scenario,
                i,
                implementations[key],
                test_result,
                conversation,
                compliant=True,
            )
        except (Exception, SystemExit) as exc:
            logger.warning(
                "Could not judge passing privacy-probe result for %s on %s: %s",
                privacy_test,
                key,
                exc,
            )
            flags["iteration_error"] = True
            return False

        if verdict == 2:
            record_verdict("Privacy TN", conversation.responses[-1].text.strip())
            logger.info("Impl %s of %s: TN", key, privacy_test)
            flags["flag1"] = True
            record_privacy_probe_validation_evidence(
                scenario, privacy_test, true_negative=True
            )
            if flags["flag1"] and flags["flag2"]:
                return False
            try:
                implementations[key] = flip_impl(
                    True, scenario, i, implementations[key], key.split()[:-1]
                )
                save_code(implementations[key], task_dict[key])
            except (Exception, SystemExit) as exc:
                logger.warning(
                    "Could not flip implementation %s to privacy-violating for %s: %s",
                    key,
                    privacy_test,
                    exc,
                )
                flags["iteration_error"] = True
                return False
        else:
            record_verdict("Privacy FN", conversation.responses[-1].text.strip())
            flags["false_negative_seen"] = True
    elif test_result["status"] == "failed":
        try:
            verdict = iterate_compliant_violating(
                scenario,
                i,
                implementations[key],
                test_result,
                conversation,
                compliant=False,
            )
        except (Exception, SystemExit) as exc:
            logger.warning(
                "Could not judge failing privacy-probe result for %s on %s: %s",
                privacy_test,
                key,
                exc,
            )
            flags["iteration_error"] = True
            return False

        if verdict == 2:
            record_verdict("Privacy TP", conversation.responses[-1].text.strip())
            logger.info("Impl %s of %s: TP", key, privacy_test)
            flags["flag2"] = True
            record_privacy_probe_validation_evidence(
                scenario, privacy_test, true_positive=True
            )
            if flags["flag1"] and flags["flag2"]:
                return False
            try:
                implementations[key] = flip_impl(
                    False, scenario, i, implementations[key], key.split()[:-1]
                )
                save_code(implementations[key], task_dict[key])
            except (Exception, SystemExit) as exc:
                logger.warning(
                    "Could not flip implementation %s to privacy-compliant for %s: %s",
                    key,
                    privacy_test,
                    exc,
                )
                flags["iteration_error"] = True
                return False
        else:
            record_verdict("Privacy FP", conversation.responses[-1].text.strip())
            flags["false_positive_seen"] = True

    if test_result["status"] == "exception" or verdict == 1:
        if test_result["status"] == "exception":
            logger.info("Exception occurred while running the privacy probe")
        else:
            logger.info(
                "Impl %s of %s: %s",
                key,
                privacy_test,
                "FN" if test_result["status"] == "passed" else "FP",
            )
        flags["flag1"] = False
        flags["flag2"] = False
        try:
            privacy_test_code = fix_privacy_probe(
                conversation,
                scenario,
                i,
                implementation=implementations[key],
                test_result=test_result,
            )
        except (Exception, SystemExit) as exc:
            logger.warning(
                "Could not repair privacy probe %s; keeping existing code: %s",
                privacy_test,
                exc,
            )
            flags["iteration_error"] = True
            return False

        if privacy_test_code:
            scenario["privacy_tests_code"][i] = privacy_test_code
            pattern = _pattern_for_probe(scenario, i)
            scenario.setdefault("privacy_probe_validation", {})[privacy_test] = {
                "pattern_id": pattern.value["id"],
                "true_positive": False,
                "true_negative": False,
                "unresolved_false_negative": False,
                "unresolved_false_positive": False,
                "statuses": [],
                "validated": False,
            }
            return False
        flags["repair_discarded"] = True
        return True
    return False
