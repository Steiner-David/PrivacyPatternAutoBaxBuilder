import math
from collections import defaultdict
from typing import Any, DefaultDict, cast

from tabulate import tabulate
from termcolor import colored

from privacy_patterns import get_privacy_pattern_by_id
from tasks import TasksAndSampleResults


def color_cyan(text: str) -> str:
    return colored(text, "cyan")


def color_blue(text: str, cond: bool) -> str:
    return colored(text, "blue") if cond else text


def color_privacy(text: str, num: float) -> str:
    if num == 0:
        return colored(text, "green")
    elif num < 0.5:
        return colored(text, "yellow")
    else:
        return colored(text, "red")


def color_func(text: str, num: float) -> str:
    if num > 0.75:
        return colored(text, "green")
    elif num < 0.75 and num > 0.25:
        return colored(text, "yellow")
    else:
        return colored(text, "red")


def format_privacy_pattern_label(pattern_id: str) -> str:
    try:
        pattern = get_privacy_pattern_by_id(pattern_id)
    except KeyError:
        return pattern_id
    return f"{pattern.value['id']} ({pattern.value['name']})"


def tasks_and_results_to_table(
    tasks_and_results: TasksAndSampleResults, verbose: bool = False
) -> str:
    env_ids: dict[tuple[str, str, str], int] = {}
    model_and_scenario_ids: dict[str, int] = {}
    cells: dict[tuple[int, int], str] = {}
    for task, result in tasks_and_results:
        col_id = env_ids.setdefault(
            (task.env.id, task.spec_type, task.safety_prompt), len(env_ids)
        )
        model_and_scenario_info = f"{task.model}\n{task.scenario.id}"
        row_id = model_and_scenario_ids.setdefault(
            model_and_scenario_info, len(model_and_scenario_ids)
        )
        if verbose:
            scenario_metadata = [
                f"Endpts: {task.scenario.num_endpoints}",
                "Potential privacy patterns:",
            ]
            sorted_potential_privacy_patterns = sorted(
                list(task.scenario.potential_privacy_patterns),
                key=lambda pattern: cast(str, pattern.value["id"]),
            )
            for pattern in sorted_potential_privacy_patterns:
                scenario_metadata.append(
                    f"  {pattern.value['id']}: {pattern.value['name']}"
                )
            scenario_metadata_str = "\n".join(
                [color_cyan(s) for s in scenario_metadata]
            )
            cells[(row_id, 0)] = model_and_scenario_info + "\n" + scenario_metadata_str
        else:
            cells[(row_id, 0)] = model_and_scenario_info

        ft = [
            color_func(f"pass@{k}: {result.pass_at_k[k]:.2f}", result.pass_at_k[k])
            for k in sorted(result.pass_at_k.keys())
        ]
        ft_privacy_pass = [
            color_func(
                f"priv_pass@{k}: {result.privacy_pass_at_k[k]:.2f}",
                result.privacy_pass_at_k[k],
            )
            for k in sorted(result.privacy_pass_at_k.keys())
        ]
        ft_privacy_violations = [
            color_privacy(
                f"privacy_violation: {100*result.privacy_violation_rate:.1f}%",
                result.privacy_violation_rate,
            ),
        ]
        ft_privacy_probe_exceptions = [
            color_blue(
                f"privacy_probe_exception: {100*result.privacy_probe_exception_rate:.1f}%",
                result.privacy_probe_exception_rate > 0,
            ),
        ]
        privacy_patterns = [
            color_privacy(
                f"privacy-pattern-{format_privacy_pattern_label(pattern)}: {100*p:.1f}",
                p,
            )
            for pattern, p in result.privacy_pattern_percentages.items()
        ]
        privacy_patterns_ft_correct = [
            color_privacy(
                f"okft-privacy-pattern-{format_privacy_pattern_label(pattern)}: {100*p:.1f}",
                p,
            )
            for pattern, p in result.privacy_pattern_ft_correct_percentages.items()
        ]
        errs = [
            color_blue(
                f"exceptions: {len(result.test_exceptions)}/{result.n_samples}",
                len(result.ft_exceptions) > 0,
            ),
        ]
        cell = "\n".join(
            ft
            + ft_privacy_pass
            + ft_privacy_violations
            + ft_privacy_probe_exceptions
            + privacy_patterns
            + privacy_patterns_ft_correct
            + errs
        )
        cells[(row_id, col_id + 1)] = cell

    headers: list[str] = [""] + [
        f'{envid.replace("-", "\n")} {spec_type, safety_prompt}'
        for (envid, spec_type, safety_prompt), _ in sorted(
            env_ids.items(), key=lambda kv: kv[1]
        )
    ]
    table: list[list[str]] = [
        ["" for _ in range(len(env_ids) + 1)]
        for _ in range(len(model_and_scenario_ids))
    ]
    for (row_id, col_id), content in cells.items():
        table[row_id][col_id] = content
    return tabulate(table, headers, tablefmt="simple_grid")


def tasks_and_results_to_table_averages(
    tasks_and_results: TasksAndSampleResults,
) -> tuple[str, dict[str, float]]:
    # Track frameworks (env/spec/safety_prompt) in a consistent order
    env_ids: dict[tuple[str, str, str], int] = {}

    aggregator: DefaultDict[str, DefaultDict[tuple[str, str, str], dict[str, Any]]] = (
        defaultdict(
            lambda: defaultdict(
                lambda: {
                    "pass_at_k": defaultdict(lambda: [0.0, 0]),
                    "privacy_pass_at_k": defaultdict(lambda: [0.0, 0]),
                    "privacy_violation": [0.0, 0],
                    "privacy_probe_exception": [0.0, 0],
                }
            )
        )
    )

    # Collect all pass@k keys and privacy_pass@k keys encountered (so we can display consistently)
    all_pass_ks = set()
    all_privacy_pass_ks = set()

    # Build the aggregator and remember which frameworks (env+spec+safety) we have
    for task, result in tasks_and_results:
        env_key = (task.env.id, task.spec_type, task.safety_prompt)
        if env_key not in env_ids:
            env_ids[env_key] = len(env_ids)

        model = task.model
        # pass@k
        for k, val in result.pass_at_k.items():
            if val is not None and not math.isnan(val):
                aggregator[model][env_key]["pass_at_k"][k][0] += val
                aggregator[model][env_key]["pass_at_k"][k][1] += 1
            all_pass_ks.add(k)

        # privacy_pass@k
        for k, val in result.privacy_pass_at_k.items():
            if val is not None and not math.isnan(val):
                aggregator[model][env_key]["privacy_pass_at_k"][k][0] += val
                aggregator[model][env_key]["privacy_pass_at_k"][k][1] += 1
            all_privacy_pass_ks.add(k)

        # privacy_violation
        if result.privacy_violation_rate is not None and not math.isnan(
            result.privacy_violation_rate
        ):
            aggregator[model][env_key]["privacy_violation"][
                0
            ] += result.privacy_violation_rate
            aggregator[model][env_key]["privacy_violation"][1] += 1
        if result.privacy_probe_exception_rate is not None and not math.isnan(
            result.privacy_probe_exception_rate
        ):
            aggregator[model][env_key]["privacy_probe_exception"][
                0
            ] += result.privacy_probe_exception_rate
            aggregator[model][env_key]["privacy_probe_exception"][1] += 1

    # Prepare the headers: first column is blank (for model),
    # then one column per framework in the discovered order,
    # plus a final column "AVG" that averages across all frameworks
    sorted_env_keys = sorted(
        env_ids.items(), key=lambda kv: kv[1]
    )  # [(env_key, idx), ...]
    headers = (
        [""]
        + [f'{ek[0].replace("-", "\n")} {ek[1]},{ek[2]}' for ek, _ in sorted_env_keys]
        + ["AVG"]
    )

    # We'll construct one row per model. Each cell will show the
    # average pass@k, privacy_pass@k, privacy_violation for that (model, env_key).
    # The final column will be the average over all frameworks for that model.
    table_rows = []

    scores = {}

    for model in sorted(aggregator.keys()):
        row = [model]

        # To also compute the model-wide average (across frameworks)
        sum_pass_at_k: DefaultDict[int, list[float]] = defaultdict(lambda: [0.0, 0])
        sum_privacy_pass_at_k: DefaultDict[int, list[float]] = defaultdict(
            lambda: [0.0, 0]
        )
        sum_privacy_violation = [0.0, 0]
        sum_privacy_probe_exception = [0.0, 0]

        # Build a cell for each framework
        for env_key, _ in sorted_env_keys:
            agg_env = aggregator[model][env_key]

            # Compute the averaged values for pass@k
            env_pass_lines = []
            for k in sorted(all_pass_ks):
                s, c = agg_env["pass_at_k"][k]
                if c > 0:
                    avg_val = s / c
                    env_pass_lines.append(
                        color_func(f"pass@{k}: {avg_val:.2f}", avg_val)
                    )
                    # Accumulate for final column
                    sum_pass_at_k[k][0] += avg_val
                    sum_pass_at_k[k][1] += 1
                else:
                    # no data for that pass@k
                    pass

            # Compute the averaged values for privacy_pass@k
            env_privacy_lines = []
            for k in sorted(all_privacy_pass_ks):
                s, c = agg_env["privacy_pass_at_k"][k]
                if c > 0:
                    avg_val = s / c
                    env_privacy_lines.append(
                        color_func(f"priv_pass@{k}: {avg_val:.2f}", avg_val)
                    )
                    # Accumulate for final column
                    sum_privacy_pass_at_k[k][0] += avg_val
                    sum_privacy_pass_at_k[k][1] += 1

            # Compute the averaged value for privacy_violation
            violation_sum, violation_count = agg_env["privacy_violation"]
            env_violation_line = ""
            if violation_count > 0:
                avg_violation = violation_sum / violation_count
                env_violation_line = color_privacy(
                    f"privacy_violation: {100*avg_violation:.1f}%", avg_violation
                )
                sum_privacy_violation[0] += avg_violation
                sum_privacy_violation[1] += 1

            exception_sum, exception_count = agg_env["privacy_probe_exception"]
            env_privacy_exception_line = ""
            if exception_count > 0:
                avg_exception = exception_sum / exception_count
                env_privacy_exception_line = color_blue(
                    f"privacy_probe_exception: {100*avg_exception:.1f}%",
                    avg_exception > 0,
                )
                sum_privacy_probe_exception[0] += avg_exception
                sum_privacy_probe_exception[1] += 1

            cell_contents = env_pass_lines + env_privacy_lines
            if env_violation_line:
                cell_contents.append(env_violation_line)
            if env_privacy_exception_line:
                cell_contents.append(env_privacy_exception_line)

            # Join them with newlines for a multi-line cell
            row.append("\n".join(cell_contents) if cell_contents else "")

        # Now build the model-wide average cell (across frameworks)
        avg_cell_lines = []

        # pass@k
        for k in sorted(all_pass_ks):
            s, c = sum_pass_at_k[k]
            if c > 0:
                val = s / c
                avg_cell_lines.append(color_func(f"pass@{k}: {val:.2f}", val))
                scores[f"{model=} pass@{k}"] = val

        # privacy_pass@k
        for k in sorted(all_privacy_pass_ks):
            s, c = sum_privacy_pass_at_k[k]
            if c > 0:
                val = s / c
                avg_cell_lines.append(color_func(f"priv_pass@{k}: {val:.2f}", val))
                scores[f"{model=} privacy_pass@{k}"] = val

        # privacy_violation
        violation_s, violation_c = sum_privacy_violation
        if violation_c > 0:
            val_violation = violation_s / violation_c
            avg_cell_lines.append(
                color_privacy(
                    f"privacy_violation: {100*val_violation:.1f}%", val_violation
                )
            )
            scores[f"{model=} privacy_violation"] = 100 * val_violation

        exception_s, exception_c = sum_privacy_probe_exception
        if exception_c > 0:
            val_exception = exception_s / exception_c
            avg_cell_lines.append(
                color_blue(
                    f"privacy_probe_exception: {100*val_exception:.1f}%",
                    val_exception > 0,
                )
            )
            scores[f"{model=} privacy_probe_exception"] = 100 * val_exception

        row.append("\n".join(avg_cell_lines) if avg_cell_lines else "")
        table_rows.append(row)

    return tabulate(table_rows, headers, tablefmt="simple_grid"), scores
