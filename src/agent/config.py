import glob
import logging
import os
import random
from argparse import ArgumentParser

import psutil

from time_utils import ProjectFormatter

logger = logging.getLogger(__name__)
logging_handler = logging.StreamHandler()
logging_handler.setFormatter(
    ProjectFormatter("%(asctime)s - %(levelname)s - %(message)s")
)
logging.basicConfig(level=logging.INFO, handlers=[logging_handler], force=True)

# Supported model providers for the agent
MODEL_PROVIDERS = ["openai", "together", "anthropic", "openrouter"]

# List of language models to use for solution generation
MODEL_LIST = [
    "deepseek/deepseek-v4-pro"
]

USE_OPENROUTER = True

# for ablation
# MODEL_LIST = [
#     "claude-sonnet-4-20250514",
#     "meta-llama/Llama-3.3-70B-Instruct-Turbo",
#     "Qwen/Qwen3-Coder-480B-A35B-Instruct-FP8",
# ]

reasoning_model = None


def get_reasoning_model():
    """Lazily construct the model used by generation/iteration agents."""
    global reasoning_model
    if reasoning_model is None:
        from models import get_model

        reasoning_model = get_model("deepseek/deepseek-v4-pro", "openrouter", True)
        # for ablation
        # reasoning_model = get_model("claude-sonnet-4-5-20250929", "anthropic", True, 32000)
    return reasoning_model


ENV_LIST = [
    "Python-FastAPI",
]

# Explicitly covered PrivacyPatterns.org patterns for the privacy benchmark workflow.
PRIVACY_PATTERN_IDS = [
    "LOCATION_GRANULARITY",
    "PSEUDONYMOUS_IDENTITY",
    "AGGREGATION_GATEWAY",
    "STRIP_INVISIBLE_METADATA",
    "SELECTIVE_ACCESS_CONTROL",
]


def get_baxbench_args(
    mode,
    model_list=MODEL_LIST,
    env_list=ENV_LIST,
    openrouter=USE_OPENROUTER,
    **kwargs,
):
    """Generate BaxBench arguments for running scenario tests.

    Args:
        mode: BaxBench mode ('generate', 'test', etc.)
        model_list: List of model names to test with
        env_list: List of environment names to test in
        openrouter: Whether to route model requests through OpenRouter
        **kwargs: Additional arguments to pass to BaxBench

    Returns:
        Parsed BaxBench arguments object
    """

    def get_random_free_port_far_from_used(
        min_port=12345, max_port=48000, safe_distance=100, max_attempts=100
    ):
        """Find a random free port that is far from any currently used ports"""
        used_ports = sorted(
            {
                conn.laddr.port
                for conn in psutil.net_connections(kind="inet")
                if conn.laddr and min_port <= conn.laddr.port <= max_port
            }
        )

        for _ in range(max_attempts):
            candidate = random.randint(min_port, max_port)
            if all(abs(candidate - used) > safe_distance for used in used_ports):
                return candidate
        raise RuntimeError("Could not find a free port after multiple attempts")

    base_args = [
        "--models",
        *model_list,
        "--mode",
        mode,
        "--temperature",
        "0",
        "--n_samples",
        "1",
        "--envs",
        *env_list,
        "--min_port",
        str(get_random_free_port_far_from_used()),
    ]

    if openrouter:
        base_args.append("--openrouter")

    for k, v in kwargs.items():
        if isinstance(v, bool):
            if v:  # flags
                base_args.append(f"--{k}")
        else:
            base_args.append(f"--{k}")
            base_args.append(str(v))

    if mode in ["generate", "test"]:
        base_args.append("-f")
    print(" ".join(base_args))
    from baxbench_wrapper import baxbench_parse_args

    return baxbench_parse_args(base_args)


parser = ArgumentParser()
parser.add_argument(
    "--difficulty",
    type=int,
    default=5,
    help="Difficulty of the backend, characterized as max. number of endpoints",
)
parser.add_argument(
    "--N_RETRIES",
    type=int,
    default=3,
    help="Max. number of attempts to fix invalid/erroronous/unparsable output in an agentic loop",
)
parser.add_argument(
    "--N_SOL_STEPS",
    type=int,
    default=5,
    help="Number of solution iteration steps",
)
parser.add_argument(
    "--N_TEST_STEPS",
    type=int,
    default=5,
    help="Number of test iteration steps",
)

parser.add_argument(
    "--N_PRIVACY_STEPS",
    type=int,
    default=5,
    help="Number of privacy probe iterations",
)

parser.add_argument(
    "--debug",
    action="store_true",
    help="Debug mode",
)
parser.add_argument(
    "--path",
    default="./artifacts/",
    help="Path to artifacts folder",
)

group = parser.add_mutually_exclusive_group(required=True)
group.add_argument(
    "--generate_scenarios", action="store_true", help="Generate scenarios"
)
group.add_argument("--generate_tests", action="store_true", help="Generate tests")
group.add_argument(
    "--generate_privacy_probes",
    action="store_true",
    help="Generate privacy probes",
)
group.add_argument(
    "--manual_test",
    metavar="APP_PY",
    help=(
        "Run already generated functional tests and privacy probes against an "
        "externally provided app.py from the manual_test folder without making "
        "any model API calls"
    ),
)

parser.add_argument(
    "--scenario",
    type=str,
    help=(
        "Scenario name (required if --generate_tests, --generate_privacy_probes, "
        "or --manual_test is set)"
    ),
)
parser.add_argument(
    "--manual_app_path",
    type=str,
    help=(
        "Optional full path override for the externally generated app.py. "
        "By default --manual_test APP_PY resolves to <manual_app_dir>/APP_PY."
    ),
)
parser.add_argument(
    "--manual_app_dir",
    type=str,
    default="./manual_test",
    help=(
        "Folder for externally generated manual app.py files. This folder is "
        "created automatically in --manual_test mode."
    ),
)
parser.add_argument(
    "--manual_model_name",
    type=str,
    default="manual-external-llm",
    help="Label used under results/ for the externally generated implementation",
)
parser.add_argument(
    "--manual_scenario_json",
    type=str,
    help=(
        "Exact generated scenario JSON artifact to use for --manual_test. "
        "If omitted, the latest <scenario>_ipN.json artifact is used."
    ),
)
parser.add_argument(
    "--manual_results_dir",
    type=str,
    default="./results",
    help="Directory where manual test results are written",
)
parser.add_argument(
    "--manual_env",
    type=str,
    default="Python-FastAPI",
    help="Environment id to use for manual testing",
)
parser.add_argument(
    "--manual_timeout",
    type=int,
    default=300,
    help="Timeout per manual functional test/privacy probe in seconds",
)
parser.add_argument(
    "--manual_num_ports",
    type=int,
    default=10000,
    help="Number of ports available to Docker containers in manual testing",
)
parser.add_argument(
    "--manual_min_port",
    type=int,
    default=12345,
    help="Minimum port number for Docker containers in manual testing",
)

args = parser.parse_args()

if (
    args.generate_tests or args.generate_privacy_probes or args.manual_test
) and not args.scenario:
    parser.error(
        "--scenario is required when using --generate_tests, "
        "--generate_privacy_probes, or --manual_test"
    )
if args.manual_test:
    os.makedirs(args.manual_app_dir, exist_ok=True)
    if not args.manual_app_path:
        if os.path.basename(args.manual_test) != args.manual_test:
            parser.error(
                "--manual_test expects a file name inside the manual_test folder. "
                "Use --manual_app_path for a full or nested path."
            )
        args.manual_app_path = os.path.join(args.manual_app_dir, args.manual_test)
    if not os.path.isfile(args.manual_app_path):
        parser.error(
            f"Manual app file not found: {args.manual_app_path}. "
            "Place the externally generated file there or pass --manual_app_path."
        )
    if args.manual_scenario_json and not os.path.isfile(args.manual_scenario_json):
        parser.error(
            f"Manual scenario JSON not found: {args.manual_scenario_json}"
        )

logger.info(f"Parsed command-line arguments: {args}")

# Verify that the provided arguments are valid
if not os.path.exists(args.path):
    parser.error(f"Invalid path {args.path}")

scenario_folder_path = os.path.join(
    args.path, args.scenario if args.scenario is not None else ""
)
if not os.path.exists(scenario_folder_path):
    parser.error(f"Invalid path {scenario_folder_path}")

if args.scenario and not os.path.isfile(
    os.path.join(scenario_folder_path, f"{args.scenario}.json")
):
    parser.error(
        f"File {args.scenario}.json not found in directory {scenario_folder_path}"
    )

for file in glob.glob(os.path.join(args.path, "token_usage*")):
    os.remove(file)
