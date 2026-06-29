# flake8: noqa F821
# mypy: disable-error-code=name-defined
import glob
import json
import os
from collections import Counter
from itertools import cycle, islice
from pathlib import PosixPath

from natsort import natsorted

import agent.config as agent_config
from agent import export_scenario_code
from agent.config import args, logger, scenario_folder_path
from agent.find_privacy_patterns import (
    find_privacy_patterns_in_code,
    find_privacy_patterns_in_scenario,
)
from agent.generate_privacy_probe_codes import generate_privacy_probe_code
from agent.generate_privacy_probe_strategies import (
    compliance_privacy_probe_strategy,
    generate_privacy_probe_strategy,
)
from agent.iterate_privacy_probes import iteration_privacy_probe
from agent.privacy_validation import (
    PrivacyValidationError,
    build_scenario_instructions,
    filter_privacy_tests_to_selected_patterns,
    filter_results_to_known_tests,
    filter_patterns_to_scenario_selection,
    prune_selected_patterns_to_generated_probes,
    record_privacy_probe_validation_evidence,
    selected_pattern_ids,
    sync_test_name_metadata,
    validate_aggregation_gateway_probe_code,
    validate_location_granularity_probe_code,
    validate_pseudonymous_identity_probe_code,
    validate_privacy_probe_coverage,
    validate_scenario_metadata,
    validate_test_metadata_consistency,
)
from agent.utils import (
    clean_code,
    save_code,
    test_and_evaluate_baxbench,
    visualize_baxbench_eval,
)
from models import Conversation


def impl_passes_all_functional_tests(
    scenario: dict, impl_key: str, full_results: dict
) -> bool:
    """Check whether an implementation passes all functional tests."""
    for test in scenario["functional_tests_names"]:
        if test not in full_results or impl_key not in full_results[test]:
            return False
        if full_results[test][impl_key].get("status") != "passed":
            return False
    return True


def summarize_functional_failures(
    scenario: dict, impl_keys: list[str], full_results: dict
) -> str:
    """Build a concise diagnostic for implementations that fail functional tests."""
    lines = []
    for impl_key in impl_keys:
        failures = []
        for test in scenario["functional_tests_names"]:
            if test not in full_results or impl_key not in full_results[test]:
                failures.append(f"{test}: missing result")
                continue
            result = full_results[test][impl_key]
            status = result.get("status", "unknown")
            if status == "passed":
                continue
            logs = (
                result.get("test_logs")
                or result.get("container_logs")
                or status
            ).strip().splitlines()
            detail = logs[-1] if logs else status
            failures.append(f"{test}: {status} ({detail[:180]})")
        if failures:
            lines.append(f"{impl_key}: " + "; ".join(failures))
    return "\n".join(lines)


def save_implementations_to_task_dirs(
    implementations: dict, task_dict: dict[str, str]
) -> None:
    for key in task_dict.keys():
        if key not in implementations:
            logger.warning("No implementation available for task key %s", key)
            continue
        save_code(implementations[key], task_dict[key])


def scenario_object_from_dict(scenario: dict):
    code = export_scenario_code(scenario, it=0, write=True, privacy=True)
    exec(code, globals())
    return globals()["SCENARIO"]


def privacy_probe_statuses(
    full_results: dict, privacy_test: str, impl_keys: list[str] | None = None
) -> list[str]:
    if privacy_test not in full_results:
        return []
    if impl_keys is None:
        impl_keys = list(full_results[privacy_test].keys())
    return [
        str(full_results[privacy_test].get(impl_key, {}).get("status", "missing"))
        for impl_key in impl_keys
    ]


def functionally_passing_impl_keys(
    scenario: dict, impl_keys: list[str], full_results: dict
) -> list[str]:
    return [
        impl_key
        for impl_key in impl_keys
        if impl_passes_all_functional_tests(scenario, impl_key, full_results)
    ]


def privacy_probes_crashing_for_all_implementations(
    scenario: dict, full_results: dict, impl_keys: list[str] | None = None
) -> list[tuple[str, list[str]]]:
    """Find probes that return None/crash for every relevant implementation."""
    crashing = []
    for privacy_test in scenario.get("privacy_tests_names", []):
        statuses = privacy_probe_statuses(
            full_results, privacy_test, impl_keys=impl_keys
        )
        if not statuses or all(
            status in {"exception", "missing"} for status in statuses
        ):
            crashing.append((privacy_test, statuses or ["missing result"]))
    return crashing


def log_privacy_probes_crashing_for_repair(
    scenario: dict,
    full_results: dict,
    phase: str,
    impl_keys: list[str] | None = None,
) -> None:
    crashing = privacy_probes_crashing_for_all_implementations(
        scenario, full_results, impl_keys=impl_keys
    )
    if not crashing:
        return
    details = "; ".join(
        f"{privacy_test} statuses={statuses}" for privacy_test, statuses in crashing
    )
    logger.warning(
        "Privacy probe validation found probe(s) that crashed or returned None on "
        "every functionally correct implementation during %s: %s. Keeping them for "
        "the privacy-probe iteration repair loop; they will still be discarded or "
        "invalidate the scenario if repair cannot produce a working probe.",
        phase,
        details,
    )


def write_privacy_probe_status(
    status: str,
    reason: str,
    scenario: dict | None = None,
    coverage_report: dict | None = None,
) -> None:
    """Persist a machine-readable privacy-probe generation status."""
    payload = {"status": status, "reason": reason}
    if scenario is not None:
        sync_test_name_metadata(scenario)
        payload["selected_privacy_patterns"] = selected_pattern_ids(scenario)
        payload["privacy_tests_names"] = scenario.get("privacy_tests_names", [])
        payload["probe_validation"] = scenario.get("privacy_probe_validation", {})
        payload["unresolved_false_negatives"] = [
            probe_name
            for probe_name, evidence in payload["probe_validation"].items()
            if isinstance(evidence, dict)
            and evidence.get("unresolved_false_negative")
        ]
        payload["missing_selected_patterns"] = prune_selected_patterns_to_generated_probes(
            scenario
        )
        if coverage_report is None:
            coverage_report = validate_privacy_probe_coverage(
                scenario,
                require_runtime_evidence=status == "complete",
            ).to_dict()
        payload["coverage_validation"] = coverage_report
    with open(
        os.path.join(scenario_folder_path, f"{args.scenario}_privacy_probe_status.json"),
        "w",
    ) as file:
        json.dump(payload, file, indent=4)


def finish_incomplete(
    reason: str, scenario: dict | None = None, coverage_report: dict | None = None
) -> None:
    logger.warning("Privacy probe generation incomplete: %s", reason)
    if scenario is not None:
        artifact_files = natsorted(
            glob.glob(
                os.path.join(scenario_folder_path, f"{args.scenario}_ip*.json")
            )
        )
        artifact_path = (
            artifact_files[-1]
            if artifact_files
            else os.path.join(scenario_folder_path, f"{args.scenario}_ip0.json")
        )
        with open(artifact_path, "w") as file:
            json.dump(scenario, file, indent=4)
    write_privacy_probe_status("incomplete", reason, scenario, coverage_report)


def safe_visualize_baxbench_eval(*args, **kwargs) -> None:
    try:
        visualize_baxbench_eval(*args, **kwargs)
    except Exception as exc:
        logger.warning("Could not visualize privacy-probe results: %s", exc)


def metadata_is_valid(
    scenario: dict, *, require_selected_privacy_probe: bool, context: str
) -> bool:
    try:
        validate_test_metadata_consistency(
            scenario,
            require_selected_privacy_probe=require_selected_privacy_probe,
        )
        return True
    except Exception as exc:
        logger.warning("Privacy metadata validation failed during %s: %s", context, exc)
        return False


def smoke_validate_privacy_probes(
    scenario: dict,
    implementations: dict,
    task_dict: dict[str, str],
    phase: str,
) -> dict:
    """Import and run generated probes before privacy-probe repair/export."""
    sync_test_name_metadata(scenario)
    validate_test_metadata_consistency(scenario, require_selected_privacy_probe=True)
    try:
        scenario_object = scenario_object_from_dict(scenario)
    except Exception as exc:
        raise RuntimeError(
            "Generated privacy benchmark failed import smoke validation during "
            f"{phase}: {exc}"
        ) from exc

    save_implementations_to_task_dirs(implementations, task_dict)
    full_results = test_and_evaluate_baxbench(scenario_object)
    filter_results_to_known_tests(scenario, full_results)

    with open(
        os.path.join(scenario_folder_path, f"{args.scenario}_results_ip0_smoke.json"),
        "w",
    ) as file:
        json.dump(full_results, file, indent=4)

    impls_filtered = functionally_passing_impl_keys(
        scenario, list(task_dict.keys()), full_results
    )
    if not impls_filtered:
        diagnostic = summarize_functional_failures(
            scenario, list(task_dict.keys()), full_results
        )
        raise RuntimeError(
            "Cannot smoke-validate privacy probes because no implementation passes "
            "all functional tests. Re-run or fix functional-test/implementation "
            "generation first.\n"
            + diagnostic
        )
    log_privacy_probes_crashing_for_repair(
        scenario, full_results, phase=phase, impl_keys=impls_filtered
    )
    validate_test_metadata_consistency(scenario, require_selected_privacy_probe=True)
    return full_results


def discard_privacy_probe(scenario: dict, i: int, privacy_test: str) -> list[str]:
    """Remove a discarded probe and keep selected-pattern metadata in sync."""
    del scenario["privacy_tests_code"][i]
    del scenario["privacy_tests_names"][i]
    missing_patterns = prune_selected_patterns_to_generated_probes(scenario)
    scenario["scenario_instructions"] = build_scenario_instructions(scenario)
    sync_test_name_metadata(scenario)
    if missing_patterns:
        logger.info(
            "Selected privacy pattern(s) now have no remaining generated probe: %s",
            ", ".join(missing_patterns),
        )
    logger.info("Discarded privacy probe %s", privacy_test)
    return missing_patterns


def discard_invalid_privacy_probes(scenario: dict) -> list[str]:
    """Remove stale generated probes that violate hard privacy-probe validation."""
    removed = []
    i = 0
    while i < len(scenario.get("privacy_tests_names", [])):
        privacy_test = scenario["privacy_tests_names"][i]
        privacy_code = scenario["privacy_tests_code"][i]
        try:
            validate_location_granularity_probe_code([privacy_code])
            validate_pseudonymous_identity_probe_code([privacy_code], scenario=scenario)
            validate_aggregation_gateway_probe_code([privacy_code])
        except PrivacyValidationError as exc:
            logger.info(
                "Discarding invalid privacy probe %s during metadata sync: %s",
                privacy_test,
                exc,
            )
            removed.append(privacy_test)
            discard_privacy_probe(scenario, i, privacy_test)
            continue
        i += 1
    return removed


def generate_privacy_probes() -> None:
    """Generate and verify privacy probes for the scenario."""
    logger.info("generating privacy probes")

    with open(
        os.path.join(scenario_folder_path, f"{args.scenario}_tasklist.json"), "rb"
    ) as file:
        task_dict = json.load(file)
    task_models = sorted({key.split()[-1] for key in task_dict})
    if task_models:
        agent_config.MODEL_LIST[:] = task_models

    implementation_files = glob.glob(
        os.path.join(scenario_folder_path, f"{args.scenario}_implementations_*.json")
    )
    baseline_implementation_files = [
        file
        for file in implementation_files
        if "_implementations_ip" not in os.path.basename(file)
    ]
    if baseline_implementation_files:
        implementation_files = baseline_implementation_files
    if not implementation_files:
        finish_incomplete("No implementation files found")
        return
    implementation_file = natsorted(implementation_files)[-1]
    with open(implementation_file, "r") as file:
        raw_implementations = json.load(file)
        implementations = {
            k: {PosixPath(path): code for path, code in v.items()}
            for k, v in raw_implementations.items()
        }

    existing_privacy_probe_files = natsorted(
        glob.glob(os.path.join(scenario_folder_path, f"{args.scenario}_ip*.json"))
    )
    scenario = None
    latest_full_results = None
    latest_privacy_probe_file = None
    for privacy_probe_file in reversed(existing_privacy_probe_files):
        with open(privacy_probe_file, "r") as file:
            candidate = json.load(file)
        try:
            validate_scenario_metadata(candidate)
        except PrivacyValidationError as exc:
            logger.warning(
                "Skipping privacy probe file %s because scenario metadata is invalid: %s",
                privacy_probe_file,
                exc,
            )
            continue
        candidate["scenario_instructions"] = build_scenario_instructions(candidate)
        removed = filter_privacy_tests_to_selected_patterns(candidate)
        if removed:
            logger.info(
                "Removed privacy probe(s) no longer selected by scenario metadata: %s",
                ", ".join(removed),
            )
        removed_patterns = prune_selected_patterns_to_generated_probes(candidate)
        if removed_patterns:
            candidate["scenario_instructions"] = build_scenario_instructions(candidate)
            logger.info(
                "Privacy probe file %s is missing selected pattern probe(s): %s",
                privacy_probe_file,
                ", ".join(removed_patterns),
            )
        discard_invalid_privacy_probes(candidate)
        sync_test_name_metadata(candidate)
        if not metadata_is_valid(
            candidate,
            require_selected_privacy_probe=True,
            context=f"loading {privacy_probe_file}",
        ):
            continue
        scenario = candidate
        latest_privacy_probe_file = privacy_probe_file
        break

    if scenario is not None:
        logger.info("loaded privacy probe file: %s", latest_privacy_probe_file)
        try:
            latest_full_results = smoke_validate_privacy_probes(
                scenario,
                implementations,
                task_dict,
                phase="loading existing privacy probes",
            )
        except (Exception, SystemExit) as exc:
            finish_incomplete(
                f"Could not smoke-validate existing privacy probes: {exc}", scenario
            )
            return
        with open(
            os.path.join(scenario_folder_path, f"{args.scenario}_ip0.json"), "w"
        ) as file:
            json.dump(scenario, file, indent=4)
    else:
        scenario_files = glob.glob(
            os.path.join(scenario_folder_path, f"{args.scenario}_i*.json")
        )
        if not scenario_files:
            finish_incomplete("No scenario files found for privacy probe generation")
            return
        latest_scenario_file = natsorted(scenario_files)[-1]

        with open(latest_scenario_file, "r") as file:
            scenario = json.load(file)
        try:
            validate_scenario_metadata(scenario)
        except PrivacyValidationError as exc:
            finish_incomplete(f"Scenario metadata is invalid: {exc}", scenario)
            return
        scenario["scenario_instructions"] = build_scenario_instructions(scenario)
        sync_test_name_metadata(scenario)

        logger.info("loaded scenario file: %s", latest_scenario_file)
        conversations = []
        searches = []

        conversation = Conversation()
        try:
            searches.append(find_privacy_patterns_in_scenario(scenario, conversation))
        except (Exception, SystemExit) as exc:
            logger.warning(
                "Privacy pattern discovery from scenario failed; using selected "
                "metadata only: %s",
                exc,
            )
            searches.append({})
        conversations.append(conversation)

        for key in task_dict.keys():
            conversation = Conversation()
            try:
                searches.append(
                    find_privacy_patterns_in_code(
                        scenario, implementations[key], conversation
                    )
                )
            except (Exception, SystemExit) as exc:
                logger.warning(
                    "Privacy pattern discovery from implementation %s failed; "
                    "using selected metadata only: %s",
                    key,
                    exc,
                )
                searches.append({})
            conversations.append(conversation)

        scenario["header_code"] = clean_code(
            "import uuid\n"
            "generate_marker = lambda: uuid.uuid4().hex\n"
            "from privacy_patterns import PrivacyPattern\n"
            + scenario["header_code"]
        )
        scenario["privacy_tests_code"] = []
        scenario["privacy_tests_names"] = []
        sync_test_name_metadata(scenario)

        pooled_patterns: dict[str, list[str]] = {}
        for found_patterns in searches:
            for pattern_id, pattern_line in filter_patterns_to_scenario_selection(
                scenario, found_patterns
            ).items():
                pooled_patterns.setdefault(pattern_id, []).append(pattern_line)

        pattern_counts = Counter(
            pattern_id
            for pattern_id, pattern_lines in pooled_patterns.items()
            if pattern_lines
        )
        logger.info("pooled privacy patterns: %s", dict(pattern_counts))

        selected_ids = selected_pattern_ids(scenario)
        for pattern_id in selected_ids:
            pattern_lines = pooled_patterns.get(
                pattern_id, [f"{pattern_id}: selected by scenario metadata."]
            )
            pattern_reasons = "\n".join(
                f"Rationale: {pattern_line}" for pattern_line in pattern_lines
            )

            conversation = Conversation()
            try:
                privacy_probe_strategy = generate_privacy_probe_strategy(
                    pattern_id, pattern_reasons, scenario, conversation
                )

                privacy_probe_strategy = compliance_privacy_probe_strategy(
                    privacy_probe_strategy, scenario, conversation
                )
            except (Exception, SystemExit) as exc:
                logger.warning(
                    "Could not generate privacy probe strategy for %s: %s",
                    pattern_id,
                    exc,
                )
                privacy_probe_strategy = ""

            if args.debug:
                logger.info(privacy_probe_strategy)

            if privacy_probe_strategy:
                try:
                    generate_privacy_probe_code(pattern_id, scenario, conversation)
                except (Exception, SystemExit) as exc:
                    logger.warning(
                        "Could not generate privacy probe code for %s: %s",
                        pattern_id,
                        exc,
                    )

        removed_patterns = prune_selected_patterns_to_generated_probes(scenario)
        if removed_patterns:
            scenario["scenario_instructions"] = build_scenario_instructions(scenario)
            logger.info(
                "Selected privacy pattern(s) have no generated probe: %s",
                ", ".join(removed_patterns),
            )
        discard_invalid_privacy_probes(scenario)
        if not metadata_is_valid(
            scenario,
            require_selected_privacy_probe=True,
            context="initial privacy probe generation",
        ):
            finish_incomplete(
                "Initial generation did not produce a probe for every selected "
                "privacy pattern",
                scenario,
            )
            return
        with open(
            os.path.join(scenario_folder_path, f"{args.scenario}_ip0.json"), "w"
        ) as file:
            json.dump(scenario, file, indent=4)
        try:
            latest_full_results = smoke_validate_privacy_probes(
                scenario,
                implementations,
                task_dict,
                phase="initial privacy probe generation",
            )
        except (Exception, SystemExit) as exc:
            finish_incomplete(
                f"Could not smoke-validate generated privacy probes: {exc}", scenario
            )
            return
        with open(
            os.path.join(scenario_folder_path, f"{args.scenario}_ip0.json"), "w"
        ) as file:
            json.dump(scenario, file, indent=4)

    try:
        code = export_scenario_code(scenario, it=0, write=True, privacy=True)
        exec(code, globals())
    except (Exception, SystemExit) as exc:
        finish_incomplete(f"Could not export initial privacy scenario: {exc}", scenario)
        return
    if not scenario["privacy_tests_names"]:
        finish_incomplete(
            "No validated privacy probes remain for "
            f"{args.scenario}. Regenerate privacy probes or regenerate the scenario; "
            "zero-probe scenarios are not valid privacy benchmark tasks.",
            scenario,
        )
        return

    it = 1
    i = 0
    while i < len(scenario["privacy_tests_names"]):
        privacy_test = scenario["privacy_tests_names"][i]
        validation_record = scenario.get("privacy_probe_validation", {}).get(
            privacy_test, {}
        )
        if validation_record.get("validated"):
            logger.info(
                "Skipping %s because persisted true-positive and true-negative "
                "validation evidence is already complete",
                privacy_test,
            )
            i += 1
            continue

        selected_implementation_file = implementation_file
        desired_historical_status = None
        if validation_record.get("true_positive") and not validation_record.get(
            "true_negative"
        ):
            desired_historical_status = "passed"
        elif validation_record.get("true_negative") and not validation_record.get(
            "true_positive"
        ):
            desired_historical_status = "failed"

        if desired_historical_status:
            historical_results_files = natsorted(
                glob.glob(
                    os.path.join(
                        scenario_folder_path, f"{args.scenario}_results_ip*.json"
                    )
                )
            )
            for historical_results_file in reversed(historical_results_files):
                suffix = os.path.basename(historical_results_file).removeprefix(
                    f"{args.scenario}_results_"
                )
                suffix = suffix.removesuffix(".json")
                historical_implementation_file = os.path.join(
                    scenario_folder_path,
                    f"{args.scenario}_implementations_{suffix}.json",
                )
                if not os.path.exists(historical_implementation_file):
                    continue
                with open(historical_results_file, "r") as file:
                    historical_results = json.load(file)
                if privacy_test not in historical_results:
                    continue
                matching_keys = [
                    key
                    for key in task_dict
                    if key in historical_results[privacy_test]
                    and historical_results[privacy_test][key].get("status")
                    == desired_historical_status
                    and impl_passes_all_functional_tests(
                        scenario, key, historical_results
                    )
                ]
                if matching_keys:
                    selected_implementation_file = historical_implementation_file
                    logger.info(
                        "Reusing functionally passing historical implementation "
                        "%s to seek missing %s evidence for %s",
                        historical_implementation_file,
                        desired_historical_status,
                        privacy_test,
                    )
                    break

        with open(selected_implementation_file, "r") as file:
            raw_implementations = json.load(file)
            implementations = {
                k: {PosixPath(path): code for path, code in v.items()}
                for k, v in raw_implementations.items()
            }
            for key in task_dict.keys():
                if key not in implementations:
                    logger.warning("No implementation available for task key %s", key)
                    continue
                save_code(implementations[key], task_dict[key])

        try:
            full_results = test_and_evaluate_baxbench(SCENARIO)
        except (Exception, SystemExit) as exc:
            finish_incomplete(
                f"Could not run privacy-probe iteration precheck for {privacy_test}: {exc}",
                scenario,
            )
            return
        latest_full_results = full_results
        filter_results_to_known_tests(scenario, full_results)
        with open(
            os.path.join(scenario_folder_path, f"{args.scenario}_results_ip0.json"),
            "w",
        ) as file:
            json.dump(full_results, file, indent=4)

        safe_visualize_baxbench_eval(
            full_results, 0, ip=True, x_axis_labels=scenario["all_tests_names"]
        )

        logger.info("Iterating %s", privacy_test)
        validation_record = scenario.get("privacy_probe_validation", {}).get(
            privacy_test, {}
        )
        flags = {
            "flag1": bool(validation_record.get("true_negative")),
            "flag2": bool(validation_record.get("true_positive")),
        }

        impls_filtered = functionally_passing_impl_keys(
            scenario, list(task_dict.keys()), full_results
        )

        if not impls_filtered:
            diagnostic = summarize_functional_failures(
                scenario, list(task_dict.keys()), full_results
            )
            finish_incomplete(
                "Cannot iterate privacy probes because no implementation passes all "
                "functional tests. Re-run or fix functional-test generation first. "
                "Common cause: a functional test requires an exact invalid-request "
                "status such as 400 when the scenario allows any 4xx.\n"
                + diagnostic,
                scenario,
            )
            return
        log_privacy_probes_crashing_for_repair(
            scenario,
            full_results,
            phase=f"iteration precheck for {privacy_test}",
            impl_keys=impls_filtered,
        )
        test_results = full_results[privacy_test]
        impl_pool = cycle(impls_filtered)

        impl_key = next(impl_pool)
        logger.info("Rotating to initial implementation %s in the pool", impl_key)

        discard = False
        for _ in range(args.N_PRIVACY_STEPS):
            try:
                discard = iteration_privacy_probe(
                    scenario,
                    i,
                    privacy_test,
                    test_results,
                    implementations,
                    flags,
                    task_dict,
                    impl_key,
                )
            except (Exception, SystemExit) as exc:
                logger.warning(
                    "Iteration for %s failed without a usable repair; the probe "
                    "will still need validation before it can be kept: %s",
                    privacy_test,
                    exc,
                )
                flags["iteration_error"] = True
                discard = False
                break
            if discard:
                logger.info("Discarding %s", privacy_test)
                discard_privacy_probe(scenario, i, privacy_test)
                sync_test_name_metadata(scenario)
                if not metadata_is_valid(
                    scenario,
                    require_selected_privacy_probe=True,
                    context=f"after discarding {privacy_test}",
                ):
                    finish_incomplete(
                        f"Discarding {privacy_test} left a selected privacy pattern "
                        "without a generated probe",
                        scenario,
                    )
                    return

            logger.info("Flags: %s", flags)
            if flags["flag1"] and flags["flag2"]:
                break

            if discard and (flags["flag1"] or flags["flag2"]):
                logger.info(
                    "Discard requested for %s after partial validation evidence; "
                    "discarding remains required because partial evidence is not "
                    "enough to validate a selected privacy pattern.",
                    privacy_test,
                )

            removed_invalid = discard_invalid_privacy_probes(scenario)
            if removed_invalid and privacy_test in removed_invalid:
                discard = True
                break
            if discard:
                break
            try:
                code = export_scenario_code(scenario, it=it, write=True, privacy=True)
                exec(code, globals())
            except (Exception, SystemExit) as exc:
                finish_incomplete(
                    f"Could not export privacy probe iteration {it}: {exc}",
                    scenario,
                )
                return
            with open(
                os.path.join(scenario_folder_path, f"{args.scenario}_ip{it}.json"), "w"
            ) as file:
                if not metadata_is_valid(
                    scenario,
                    require_selected_privacy_probe=True,
                    context=f"writing privacy probe iteration {it}",
                ):
                    finish_incomplete(
                        f"Privacy metadata became invalid while writing ip{it}",
                        scenario,
                    )
                    return
                json.dump(scenario, file, indent=4)

            if flags["flag1"] or flags["flag2"]:
                try:
                    full_results = test_and_evaluate_baxbench(
                        SCENARIO, [impl_key.split()[-1]]
                    )
                    latest_full_results = full_results
                except (Exception, SystemExit) as exc:
                    logger.warning(
                        "Focused privacy-probe test run failed for %s on %s: %s",
                        privacy_test,
                        impl_key,
                        exc,
                    )
                    flags["iteration_error"] = True
                    break
            else:
                try:
                    full_results = test_and_evaluate_baxbench(SCENARIO)
                    latest_full_results = full_results
                except (Exception, SystemExit) as exc:
                    logger.warning(
                        "Privacy-probe test run failed for %s: %s",
                        privacy_test,
                        exc,
                    )
                    flags["iteration_error"] = True
                    break

            if not discard:
                filter_results_to_known_tests(scenario, full_results)
                if privacy_test not in full_results:
                    logger.warning(
                        "Result set did not include privacy probe %s; stopping "
                        "iteration for this probe.",
                        privacy_test,
                    )
                    flags["iteration_error"] = True
                    break
                current_impls_filtered = functionally_passing_impl_keys(
                    scenario, list(full_results[privacy_test].keys()), full_results
                )
                log_privacy_probes_crashing_for_repair(
                    scenario,
                    full_results,
                    phase=f"iteration {it} for {privacy_test}",
                    impl_keys=current_impls_filtered or None,
                )
                test_results = full_results[privacy_test]

            with open(
                os.path.join(
                    scenario_folder_path, f"{args.scenario}_results_ip{it}.json"
                ),
                "w",
            ) as file:
                filter_results_to_known_tests(scenario, full_results)
                json.dump(full_results, file, indent=4)
            with open(
                os.path.join(
                    scenario_folder_path,
                    f"{args.scenario}_implementations_ip{it}.json",
                ),
                "w",
            ) as file:
                json.dump(
                    {
                        k: {str(path): code for path, code in v.items()}
                        for k, v in implementations.items()
                    },
                    file,
                    indent=4,
                )

            safe_visualize_baxbench_eval(
                full_results,
                it,
                ip=True,
                highlight_x=privacy_test if not discard else None,
                x_axis_labels=scenario["all_tests_names"],
            )

            prev_impl_key = impl_key
            implementation_was_reset = False
            while not impl_passes_all_functional_tests(
                scenario, impl_key, full_results
            ):
                logger.warning(
                    "Implementation %s failed functional tests while iterating %s; resetting it",
                    impl_key,
                    privacy_test,
                )
                with open(selected_implementation_file, "r") as file:
                    raw_implementations = json.load(file)
                    implementations[impl_key] = {
                        PosixPath(path): code
                        for path, code in raw_implementations[impl_key].items()
                    }
                    save_code(implementations[impl_key], task_dict[impl_key])
                    implementation_was_reset = True

                impl_key = next(impl_pool)
                logger.info("Rotating to next implementation %s in the pool", impl_key)
                if impl_key == prev_impl_key:
                    break

            if implementation_was_reset:
                try:
                    full_results = test_and_evaluate_baxbench(SCENARIO)
                    latest_full_results = full_results
                except (Exception, SystemExit) as exc:
                    logger.warning(
                        "Could not retest restored implementation for %s: %s",
                        privacy_test,
                        exc,
                    )
                    flags["iteration_error"] = True
                    break
                filter_results_to_known_tests(scenario, full_results)
                if not impl_passes_all_functional_tests(
                    scenario, impl_key, full_results
                ):
                    logger.warning(
                        "Restored implementation %s still fails functional tests "
                        "while iterating %s",
                        impl_key,
                        privacy_test,
                    )
                    flags["iteration_error"] = True
                    break
                test_results = full_results[privacy_test]

            it += 1
            if discard or flags.get("iteration_error"):
                break

        if flags["flag1"] and flags["flag2"]:
            logger.info("Successfully iterated %s, both flags are True", privacy_test)
            record_privacy_probe_validation_evidence(
                scenario,
                privacy_test,
                true_positive=True,
                true_negative=True,
                statuses=privacy_probe_statuses(
                    latest_full_results or full_results,
                    privacy_test,
                ),
            )
            i += 1
        elif flags.get("iteration_error"):
            finish_incomplete(
                f"Iteration for {privacy_test} stopped after a transient model or "
                "execution error; preserving the probe and any validated evidence",
                scenario,
            )
            return
        elif not discard:
            logger.info(
                "Failed to iterate %s, flag1=%s, flag2=%s",
                privacy_test,
                flags["flag1"],
                flags["flag2"],
            )
            if flags.get("false_negative_seen"):
                record_privacy_probe_validation_evidence(
                    scenario,
                    privacy_test,
                    unresolved_false_negative=True,
                    statuses=privacy_probe_statuses(
                        latest_full_results or full_results,
                        privacy_test,
                    ),
                )
            if flags.get("false_positive_seen"):
                record_privacy_probe_validation_evidence(
                    scenario,
                    privacy_test,
                    unresolved_false_positive=True,
                    statuses=privacy_probe_statuses(
                        latest_full_results or full_results,
                        privacy_test,
                    ),
                )
            discard_privacy_probe(scenario, i, privacy_test)
            sync_test_name_metadata(scenario)
            if not metadata_is_valid(
                scenario,
                require_selected_privacy_probe=True,
                context=f"after discarding {privacy_test}",
            ):
                finish_incomplete(
                    f"{privacy_test} was not validated and removing it left a "
                    "selected privacy pattern without a working probe",
                    scenario,
                )
                return

            try:
                code = export_scenario_code(scenario, it=it, write=True, privacy=True)
                exec(code, globals())
            except (Exception, SystemExit) as exc:
                finish_incomplete(
                    f"Could not export post-discard privacy scenario ip{it}: {exc}",
                    scenario,
                )
                return
            with open(
                os.path.join(scenario_folder_path, f"{args.scenario}_ip{it}.json"), "w"
            ) as file:
                if not metadata_is_valid(
                    scenario,
                    require_selected_privacy_probe=True,
                    context=f"writing post-discard privacy probe iteration {it}",
                ):
                    finish_incomplete(
                        f"Privacy metadata became invalid after discarding {privacy_test}",
                        scenario,
                    )
                    return
                json.dump(scenario, file, indent=4)

            try:
                full_results = test_and_evaluate_baxbench(
                    SCENARIO,
                    [key.split()[-1] for key in islice(impl_pool, len(impls_filtered))],
                )
                latest_full_results = full_results
            except (Exception, SystemExit) as exc:
                finish_incomplete(
                    f"Could not run post-discard privacy tests for {privacy_test}: {exc}",
                    scenario,
                )
                return

            with open(
                os.path.join(
                    scenario_folder_path, f"{args.scenario}_results_ip{it}.json"
                ),
                "w",
            ) as file:
                filter_results_to_known_tests(scenario, full_results)
                json.dump(full_results, file, indent=4)
            with open(
                os.path.join(
                    scenario_folder_path,
                    f"{args.scenario}_implementations_ip{it}.json",
                ),
                "w",
            ) as file:
                json.dump(
                    {
                        k: {str(path): code for path, code in v.items()}
                        for k, v in implementations.items()
                    },
                    file,
                    indent=4,
                )
            safe_visualize_baxbench_eval(
                full_results, it, ip=True, x_axis_labels=scenario["all_tests_names"]
            )
            it += 1

    if not metadata_is_valid(
        scenario, require_selected_privacy_probe=True, context="final privacy export"
    ):
        finish_incomplete("Final privacy metadata is invalid", scenario)
        return

    final_artifact_files = natsorted(
        glob.glob(os.path.join(scenario_folder_path, f"{args.scenario}_ip*.json"))
    )
    final_artifact_path = (
        final_artifact_files[-1]
        if final_artifact_files
        else os.path.join(scenario_folder_path, f"{args.scenario}_ip0.json")
    )
    final_iteration_match = os.path.basename(final_artifact_path).removesuffix(
        ".json"
    ).rsplit("_ip", 1)
    final_iteration = (
        int(final_iteration_match[1])
        if len(final_iteration_match) == 2
        and final_iteration_match[1].isdigit()
        else 0
    )
    export_scenario_code(
        scenario, it=final_iteration, write=True, privacy=True
    )
    with open(final_artifact_path, "w") as file:
        json.dump(scenario, file, indent=4)

    coverage = validate_privacy_probe_coverage(
        scenario,
        latest_full_results,
        require_runtime_evidence=True,
    )
    if not coverage.valid:
        finish_incomplete(
            "Final privacy probe coverage is invalid: "
            + "; ".join(coverage.errors),
            scenario,
            coverage.to_dict(),
        )
        return

    write_privacy_probe_status(
        "complete",
        "Privacy probe generation completed",
        scenario,
        coverage.to_dict(),
    )
