import hashlib
import importlib.util
import json
import logging
import re
import shutil
import sys
import tempfile
from argparse import Namespace
from datetime import datetime, timezone
from pathlib import Path


def find_latest_privacy_scenario_json(
    scenario_folder_path: str | Path, scenario_name: str
) -> Path:
    """Find the newest generated privacy-probe scenario artifact."""
    scenario_folder = Path(scenario_folder_path)
    candidates: list[tuple[int, Path]] = []
    pattern = re.compile(rf"^{re.escape(scenario_name)}_ip(\d+)\.json$")
    for path in scenario_folder.glob(f"{scenario_name}_ip*.json"):
        match = pattern.match(path.name)
        if match:
            candidates.append((int(match.group(1)), path))
    if not candidates:
        raise FileNotFoundError(
            "No privacy-probe scenario artifact found. Expected a file like "
            f"{scenario_name}_ipN.json in {scenario_folder}."
        )
    return max(candidates, key=lambda item: item[0])[1]


def find_latest_functional_scenario_json(
    scenario_folder_path: str | Path, scenario_name: str
) -> Path:
    """Find the newest generated functional-test scenario artifact."""
    scenario_folder = Path(scenario_folder_path)
    candidates: list[tuple[int, Path]] = []
    pattern = re.compile(rf"^{re.escape(scenario_name)}_iu(\d+)\.json$")
    for path in scenario_folder.glob(f"{scenario_name}_iu*.json"):
        match = pattern.match(path.name)
        if match:
            candidates.append((int(match.group(1)), path))
    if not candidates:
        raise FileNotFoundError(
            "No functional-test scenario artifact found. Expected a file like "
            f"{scenario_name}_iuN.json in {scenario_folder}."
        )
    return max(candidates, key=lambda item: item[0])[1]


def find_latest_manual_scenario_json(
    scenario_folder_path: str | Path, scenario_name: str
) -> Path:
    """Find the newest scenario artifact usable for manual testing."""
    try:
        return find_latest_privacy_scenario_json(scenario_folder_path, scenario_name)
    except FileNotFoundError:
        return find_latest_functional_scenario_json(
            scenario_folder_path, scenario_name
        )


def load_manual_scenario_payload(path: str | Path) -> dict:
    """Load and sanity-check a frozen scenario artifact for manual evaluation."""
    scenario_path = Path(path)
    with open(scenario_path, "r", encoding="utf-8") as file:
        scenario = json.load(file)

    if not scenario.get("functional_tests_code"):
        raise ValueError(f"{scenario_path} does not contain functional tests.")
    if not scenario.get("functional_tests_names"):
        raise ValueError(f"{scenario_path} does not contain functional test names.")
    return scenario


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _select_env(env_id: str):
    from env import all_envs

    for env in all_envs:
        if env.id == env_id:
            return env
    valid = ", ".join(sorted(env.id for env in all_envs))
    raise ValueError(f"Unknown manual environment {env_id!r}. Valid values: {valid}")


def _forbid_model_api_calls() -> None:
    def fail(*_args, **_kwargs):
        raise RuntimeError("manual_test mode forbids model API calls")

    try:
        import agent.utils as agent_utils

        agent_utils.generate_with_retries = fail
    except Exception:
        pass
    for module_name, module in list(sys.modules.items()):
        if module_name.startswith("agent.") and hasattr(
            module, "generate_with_retries"
        ):
            setattr(module, "generate_with_retries", fail)
    try:
        import prompts

        prompts.Prompter.prompt_model = fail
        prompts.Prompter.prompt_model_batch_with_exp_backoff = fail
    except Exception:
        pass


def _load_manual_scenario_module(scenario_id: str, code: str):
    """Load generated scenario code as an importable module for multiprocessing."""
    safe_id = re.sub(r"\W+", "_", scenario_id).strip("_") or "scenario"
    digest = hashlib.sha256(code.encode("utf-8")).hexdigest()[:12]
    module_name = f"_manual_scenario_{safe_id}_{digest}"
    module_dir = Path(tempfile.gettempdir()) / "privacy_pattern_manual_scenarios"
    module_dir.mkdir(parents=True, exist_ok=True)
    module_path = module_dir / f"{module_name}.py"
    module_path.write_text(code, encoding="utf-8")
    if str(module_dir) not in sys.path:
        sys.path.insert(0, str(module_dir))

    spec = importlib.util.spec_from_file_location(module_name, module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not load manual scenario module from {module_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def _scenario_object_from_payload(scenario: dict):
    from agent.export import export_scenario_code

    include_privacy = bool(
        scenario.get("privacy_tests_code") or scenario.get("privacy_tests_names")
    )
    code = export_scenario_code(scenario, write=False, privacy=include_privacy)
    scenario_id = str(scenario.get("title") or scenario.get("id") or "scenario")
    module = _load_manual_scenario_module(scenario_id, code)
    return module.SCENARIO


def _write_manual_run_metadata(
    *,
    task,
    env,
    scenario_object,
    app_path: Path,
    scenario_json_path: Path,
    results_dir: Path,
) -> None:
    save_dir = task.get_save_dir(results_dir)
    save_dir.mkdir(parents=True, exist_ok=True)
    prompt = scenario_object.build_prompt(env, "openapi", "none")
    metadata = {
        "mode": "manual_test",
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "note": "No model API call is made by the pipeline in manual_test mode.",
        "manual_model_name": task.model,
        "manual_app_path": str(app_path),
        "manual_app_sha256": _sha256_file(app_path),
        "scenario_json_path": str(scenario_json_path),
        "scenario_id": scenario_object.id,
        "environment": env.id,
        "spec_type": "openapi",
        "safety_prompt": "none",
        "sample": 0,
    }
    with open(save_dir / "manual_metadata.json", "w", encoding="utf-8") as file:
        json.dump(metadata, file, indent=4)
    with open(save_dir / "gen.log", "w", encoding="utf-8") as file:
        file.write(
            "Manual external implementation. The pipeline did not call a model API.\n"
        )
        file.write(f"Scenario artifact: {scenario_json_path}\n")
        file.write(f"Source app.py: {app_path}\n")
        file.write(f"Source app.py sha256: {metadata['manual_app_sha256']}\n")
        file.write("\nPublic prompt to use for fair external generation:\n")
        file.write(prompt)
        file.write("\n")


def _manual_test_axis_labels(scenario: dict, full_results: dict) -> list[str]:
    labels = list(scenario.get("all_tests_names") or [])
    if labels:
        return labels
    return list(scenario.get("functional_tests_names") or []) + list(
        scenario.get("privacy_tests_names") or []
    ) or list(full_results.keys())


def _manual_heatmap_results(
    *, full_results: dict, env, model_name: str
) -> dict[str, dict[str, dict]]:
    safe_model_name = re.sub(r"\s+", "-", str(model_name).strip()) or "manual-model"
    row_label = f"{env.language} {env.framework} {safe_model_name}"
    return {
        test_name: {row_label: result}
        for test_name, result in full_results.items()
        if isinstance(result, dict) and "status" in result
    }


def _write_manual_results_heatmap(
    *, task, env, scenario: dict, results_dir: Path, sample: int = 0
) -> Path | None:
    from agent.utils import visualize_baxbench_eval

    result_path = task.get_test_results_json_path(results_dir, sample)
    if not result_path.exists():
        return None
    with open(result_path, "r", encoding="utf-8") as file:
        result_payload = json.load(file)
    full_results = result_payload.get("full_results") or {}
    if not isinstance(full_results, dict) or not full_results:
        return None

    heatmap_results = _manual_heatmap_results(
        full_results=full_results,
        env=env,
        model_name=task.model,
    )
    if not heatmap_results:
        return None

    output_path = result_path.with_suffix(".png")
    visualize_baxbench_eval(
        heatmap_results,
        "",
        iv=True,
        x_axis_labels=_manual_test_axis_labels(scenario, full_results),
        output_path=output_path,
    )
    return output_path


def run_manual_test(args: Namespace) -> Path:
    """Run frozen functional tests and privacy probes against a provided app.py."""
    logger = logging.getLogger(__name__)
    _forbid_model_api_calls()
    scenario_folder_path = Path(args.path) / args.scenario
    scenario_json_path = (
        Path(args.manual_scenario_json)
        if args.manual_scenario_json
        else find_latest_manual_scenario_json(scenario_folder_path, args.scenario)
    )
    app_path = Path(args.manual_app_path).resolve()
    results_dir = Path(args.manual_results_dir)

    scenario_payload = load_manual_scenario_payload(scenario_json_path)
    scenario_object = _scenario_object_from_payload(scenario_payload)
    env = _select_env(args.manual_env)
    if not env.code_filename:
        raise ValueError(
            f"Manual single-file app testing requires an environment with code_filename; "
            f"{env.id} is multi-file."
        )

    from tasks import Task, TaskHandler

    task = Task(
        env=env,
        scenario=scenario_object,
        model=args.manual_model_name,
        temperature=0.0,
        reasoning_effort="manual",
        spec_type="openapi",
        safety_prompt="none",
        openrouter=False,
    )

    code_dir = task.get_code_dir(results_dir, 0)
    if code_dir.exists():
        shutil.rmtree(code_dir)
    with open(app_path, "r", encoding="utf-8") as file:
        app_code = file.read()
    task.save_code({Path(env.code_filename): app_code}, results_dir, 0)
    _write_manual_run_metadata(
        task=task,
        env=env,
        scenario_object=scenario_object,
        app_path=app_path,
        scenario_json_path=scenario_json_path,
        results_dir=results_dir,
    )

    handler = TaskHandler(
        tasks=[task], results_dir=results_dir, max_concurrent_runs=1
    )
    handler.run_tests(
        samples=[0],
        timeout=args.manual_timeout,
        num_ports=args.manual_num_ports,
        min_port=args.manual_min_port,
        force=True,
    )
    result_path = task.get_test_results_json_path(results_dir, 0)
    try:
        heatmap_path = _write_manual_results_heatmap(
            task=task,
            env=env,
            scenario=scenario_payload,
            results_dir=results_dir,
            sample=0,
        )
        if heatmap_path is not None:
            logger.info("Manual test heatmap written to %s", heatmap_path)
    except Exception as exc:
        logger.warning("Could not visualize manual test results: %s", exc)
    logger.info("Manual test complete. Results written to %s", result_path)
    return result_path
