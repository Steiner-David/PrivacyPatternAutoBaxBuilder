import scenarios.base
import scenarios.privacy

# Default benchmark scenarios for the privacy-pattern workflow.
all_scenarios: list[scenarios.base.Scenario] = list(scenarios.privacy.SCENARIOS)
