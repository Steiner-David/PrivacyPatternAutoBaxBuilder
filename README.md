# PrivacyPatternAutoBaxBuilder

PrivacyPatternAutoBaxBuilder is an AutoBaxBuilder/BaxBench-style benchmark pipeline for testing whether code-generating LLMs implement selected PrivacyPatterns.org patterns in backend applications.

The project generates or loads backend API scenarios, creates functional tests, generates model implementations, creates privacy probes, runs everything in Docker, and reports both functional correctness and privacy-aware metrics. It is a benchmark for code-observable privacy behavior; it does not claim legal compliance and it does not cover every privacy pattern.

## AutoBaxBuilder Attribution and Citation

This project adapts the architecture and implementation of [AutoBaxBuilder](https://github.com/eth-sri/AutoBaxBuilder), introduced in [AutoBaxBuilder: Bootstrapping Code Security Benchmarking](https://arxiv.org/abs/2512.21132), for privacy-pattern benchmarking. AutoBaxBuilder generates backend benchmark scenarios, functional tests, implementations, and security probes. This project extends that workflow with privacy-pattern metadata, privacy probes, validation, and privacy-aware metrics.

Please cite the original AutoBaxBuilder work when using this repository:

```bibtex
@article{vonarx2025autobaxbuilderbootstrappingcodesecurity,
  title={AutoBaxBuilder: Bootstrapping Code Security Benchmarking},
  author={Tobias von Arx and Niels Mündler and Mark Vero and Maximilian Baader and Martin Vechev},
  year={2025},
  eprint={2512.21132},
  archivePrefix={arXiv}
}
```

## Academic Context

This tool was created for the course **Privacy Engineering in Practice (PEng in Practice)** at the **University of Salzburg**.

## What This Repository Does

The main workflow is:

```text
scenario generation
-> functional test generation and repair
-> implementation generation and repair
-> privacy probe generation and validation
-> Docker execution
-> metrics, logs, heatmaps, and artifacts
```

Generated benchmark artifacts are stored under `artifacts/<ScenarioName>/`. Model or manual app executions are stored under `results/<model>/<scenario>/<environment>/...`.

## Supported Privacy Patterns

The benchmark code currently recognizes these PrivacyPatterns.org patterns:

- `LOCATION_GRANULARITY`: Location Granularity, https://privacypatterns.org/patterns/Location-granularity
- `PSEUDONYMOUS_IDENTITY`: Pseudonymous Identity, https://privacypatterns.org/patterns/Pseudonymous-identity
- `AGGREGATION_GATEWAY`: Aggregation Gateway, https://privacypatterns.org/patterns/Aggregation-gateway
- `STRIP_INVISIBLE_METADATA`: Strip Invisible Metadata, https://privacypatterns.org/patterns/Strip-invisible-metadata
- `SELECTIVE_ACCESS_CONTROL`: Selective Access Control, https://privacypatterns.org/patterns/Selective-Access-Control

Generated scenarios must explicitly select patterns and include privacy metadata such as personal data, declared purpose, allowed and forbidden use, allowed and forbidden storage, and expected preserving or violating behavior.

## Setup

The Docker workflow is recommended because benchmark execution itself uses Docker containers.

```bash
docker build \
  --build-arg UID=$(id -u) \
  --build-arg GID=$(id -g) \
  --build-arg DOCKER_GID=$(getent group docker | cut -d: -f3) \
  -t autobaxbuilder .
```

If `getent` is unavailable, use the Docker socket group id instead:

```bash
docker build \
  --build-arg UID=$(id -u) \
  --build-arg GID=$(id -g) \
  --build-arg DOCKER_GID=$(stat -c '%g' /var/run/docker.sock) \
  -t autobaxbuilder .
```

Create an environment-variable file for the providers you use. In the examples below, `/path/to/your.env` should be the path to that file. If the file is named `.env` and lives at the repository root, use `.env`.

```bash
export OPENAI_API_KEY="<your_api_key>"
export TOGETHER_API_KEY="<your_api_key>"
export ANTHROPIC_API_KEY="<your_api_key>"
export OPENROUTER_API_KEY="<your_api_key>"
```

Run the project container:

```bash
./start_docker.sh /path/to/your.env
```

`start_docker.sh` defaults to `.env` when no argument is passed. Pass a different path if your environment-variable file lives elsewhere.

Equivalent explicit command:

```bash
docker run \
  --network host \
  --env-file /path/to/your.env \
  -e TZ=Europe/Vienna \
  -e AUTOBAX_TIMEZONE=Europe/Vienna \
  -it \
  --memory="4g" \
  --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$(pwd)":/app \
  autobaxbuilder /bin/bash
```

## Generate a Benchmark Scenario

Run all commands from the repository root.

```bash
python src/main.py --generate_scenarios
```

This creates `artifacts/<ScenarioName>/<ScenarioName>.json`. Scenario generation uses the configured reasoning model in `src/agent/config.py`.

Useful options:

- `--difficulty N`: target maximum number of endpoints.
- `--N_RETRIES N`: repair attempts for invalid or unparsable model output.
- `--path PATH`: artifact root; defaults to `./artifacts/`.
- `--debug`: verbose generation logging.

## Generate Functional Tests and Implementations

After a scenario JSON exists:

```bash
python src/main.py \
  --generate_tests \
  --scenario ScenarioName
```

This creates functional-test artifacts such as:

- `ScenarioName_iu0.json` and `ScenarioName_iu0.py`
- `ScenarioName_tasklist.json`
- `ScenarioName_implementations_itN.json`
- `ScenarioName_results_itN.json`
- `ScenarioName_implementations_iuN.json`
- `ScenarioName_results_iuN.json`
- `ScenarioName_results_itN.png` and `ScenarioName_results_iuN.png`

The command generates app implementations through BaxBench, runs generated tests in Docker, repairs implementations with black-box feedback, then repairs tests with white-box feedback.

## Generate Privacy Probes

After functional tests and implementations exist:

```bash
python src/main.py \
  --generate_privacy_probes \
  --scenario ScenarioName
```

This adds privacy probes and validates coverage for the scenario-selected patterns. Outputs include:

- `ScenarioName_ipN.json` and `ScenarioName_ipN.py`
- `ScenarioName_results_ipN.json`
- `ScenarioName_implementations_ipN.json`
- `ScenarioName_results_ipN.png`
- `ScenarioName_results_ip0_smoke.json`
- `ScenarioName_privacy_probe_status.json`

`ScenarioName_privacy_probe_status.json` is the machine-readable verdict for probe generation. A status of `complete` means every selected pattern has a validated probe with runtime evidence. A status of `incomplete` means the command returned cleanly, but the benchmark instance should not be treated as usable until the reported coverage, import, runtime, false-positive, or false-negative issue is fixed.

## Generation Guardrails

The generator and validators enforce several benchmark-specific constraints:

- Scenario metadata must include the selected PrivacyPatterns.org pattern IDs and privacy-oracle fields.
- Functional tests must check ordinary API behavior only; privacy checks belong in privacy probes.
- Public implementation prompts are sanitized so they do not reveal the benchmark oracle terms directly.
- Pseudonymous Identity scenarios use an explicit mode: public pseudonymity or storage-level pseudonymity.
- Aggregation Gateway scenarios must allow aggregate state such as count, sum, total, average, or mean, and must not require returning individual raw records.
- Aggregation Gateway probes distinguish raw individual records from aggregate state; an aggregate value equaling a submitted value is not by itself a violation.
- Privacy probes are filtered to the scenario-selected patterns and must import, run, and provide runtime validation evidence before the final status can be `complete`.
- Probes that crash for every functionally correct implementation are retained for repair instead of silently being accepted.

## Manual External App Testing

Manual mode evaluates an externally produced single-file implementation against an already generated scenario and its frozen tests. It does not call a model API.

Place the implementation in `manual_test/` and provide its filename:

```bash
python src/main.py \
  --manual_test app.py \
  --scenario SCENARIO_NAME
```

Relevant optional arguments:

- `--manual_app_path PATH`: use an implementation outside the default `manual_test/` location.
- `--manual_scenario_json PATH`: select an exact generated test suite instead of the latest available one.
- `--manual_model_name LABEL`: choose the label used to group the results.
- `--manual_results_dir PATH`: change the output directory.

The run stores the evaluated implementation, metadata, logs, structured test results, and a heatmap when visualization succeeds.

## Metrics

Evaluation reports:

- `pass@k`: functional correctness only.
- `privacy_pass@k`: functional correctness plus no privacy findings and no privacy probe exceptions.
- `privacy_violation_rate`: fraction of functionally correct samples that failed at least one privacy probe.
- `privacy_probe_exception_rate`: fraction of functionally correct samples where at least one privacy probe crashed, returned `None`, or no privacy probe was available.
- `privacy_pattern_percentages`: per-pattern violation frequency across all samples.
- `privacy_pattern_ft_correct_percentages`: per-pattern violation frequency among functionally correct samples.

Privacy probes return:

- `set()`: no privacy-pattern violation detected.
- `{PrivacyPattern.X}`: violation detected for one or more patterns.
- `None`: probe could not complete and is recorded as an exception.
