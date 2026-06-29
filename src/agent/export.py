import os

import agent.templates as templates
from agent.config import args, logger, scenario_folder_path
from agent.generated_imports import ensure_generated_test_runtime_imports
from agent.privacy_validation import (
    public_implementation_description,
    validate_test_metadata_consistency,
)


def export_scenario_code(
    scenario: dict,
    it: int = 0,
    iv: bool = False,
    write: bool = True,
    privacy: bool = False,
) -> str:
    """Export scenario data to a Python code file.

    Args:
        scenario: Dictionary containing scenario data including:
            - header_code: Import statements and helper code
            - functional_tests_code: List of functional test implementations
            - privacy_tests_code: List of privacy probe implementations (if privacy=True)
            - schema: OpenAPI schema specification
            - text_spec: Text description of the scenario
            - title, description: Scenario metadata
            - needs_db, needs_secret: Resource requirements
            - scenario_instructions: Setup instructions
            - functional_tests_names: List of functional test names
            - privacy_tests_names: List of privacy probe names (if privacy=True)
            - needed_packages: Optional list of required packages
        it: Iteration number for naming (used in _iu{it} or _iw{it} suffix)
        iv: If True, generates an "iv" (verified) version file
        write: If True, writes the code to a file; if False, only returns the code string
        privacy: If True, includes privacy probes in the export

    Returns:
        The generated Python code as a string
    """
    validate_test_metadata_consistency(
        scenario, require_selected_privacy_probe=privacy
    )
    public_description = public_implementation_description(scenario)

    needed_packages_param = ""
    if "needed_packages" in scenario:
        needed_packages_param = f"\n    needed_packages={scenario['needed_packages']},"
    privacy_tests_code = scenario.get("privacy_tests_code", [])
    privacy_tests_names = scenario.get("privacy_tests_names", [])
    tests_code = "\n\n".join(scenario["functional_tests_code"])
    if privacy:
        tests_code = "\n\n".join(scenario["functional_tests_code"] + privacy_tests_code)
    header_code = ensure_generated_test_runtime_imports(
        scenario["header_code"], tests_code
    )
    if not privacy:
        code = templates.scenario_file.format(
            header_code=header_code,
            tests_code=tests_code,
            scenario_openapi=scenario["schema"],
            scenario_textspec=scenario["text_spec"],
            scenario_title=scenario["title"],
            scenario_description=public_description,
            scenario_needsdb=scenario["needs_db"],
            scenario_needssecret=scenario["needs_secret"],
            scenario_instructions=scenario["scenario_instructions"],
            scenario_functional_tests_names=", ".join(
                scenario["functional_tests_names"]
            ),
            scenario_privacy_tests_names="",
            scenario_needed_packages=needed_packages_param,
        )
    else:
        code = templates.scenario_file.format(
            header_code=header_code,
            tests_code=tests_code,
            scenario_openapi=scenario["schema"],
            scenario_textspec=scenario["text_spec"],
            scenario_title=scenario["title"],
            scenario_description=public_description,
            scenario_needsdb=scenario["needs_db"],
            scenario_needssecret=scenario["needs_secret"],
            scenario_instructions=scenario["scenario_instructions"],
            scenario_functional_tests_names=", ".join(
                scenario["functional_tests_names"]
            ),
            scenario_privacy_tests_names=", ".join(privacy_tests_names),
            scenario_needed_packages=needed_packages_param,
        )

    if not iv:
        full_path = os.path.join(scenario_folder_path, f"{args.scenario}_iu{it}.py")
    else:
        full_path = os.path.join(scenario_folder_path, f"{args.scenario}_iv.py")

    if privacy:
        full_path = os.path.join(scenario_folder_path, f"{args.scenario}_ip{it}.py")

    if not write:
        return code

    with open(full_path, "w") as file:
        file.write(code)

    logger.info(f"Wrote scenario to {full_path}")

    return code
