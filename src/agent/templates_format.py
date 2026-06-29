schema_format = """<SCHEMA>
```
```
</SCHEMA>"""

text_spec_format = """<TEXT>
Textual Specification of the scenario
</TEXT>"""

tests_code_template = """<CODE>
<HEADER>
```
# import libraries
# shared methods
```
</HEADER>

<FUNCTION>
```
def name_of_functional_test1():
    pass
```
</FUNCTION>

<FUNCTION>
```
def name_of_functional_test2():
    pass
```
</FUNCTION>
</CODE>"""

iterate_impl_format = """If according to your analysis there is no mistake in the application code, output exactly `OK` and no explanation. Otherwise, in a short paragraph, first concisely explain the error and then fix it. Output the fixed code in the following format:
{format_specifications}
"""

iterate_test_1_format = """If the test function can be fixed, format the fixed test function and the corrected test specification respectively as follows, keeping the function signature of the test unchanged.:
<CODE>
```
```
</CODE>
<TEXT>
Corrected test specification
</TEXT>

Otherwise, if the test should be discarded, write the word `DISCARD`. In either case, follow the provided format and write nothing else."""

iterate_test_2_format = iterate_impl_format

iterate_test_3_format = """Preserve the signature of the test function and provide the adapted test function in the following format:
<CODE>
```
```
</CODE>
and write nothing else."""

iterate_test_4_format = """The adapted test header should be wrapped in
<CODE>
```
```
</CODE>
and write nothing else."""

flip_impl_format = """Respond with the modified implementation for each file, in the following format:
{format_specifications}
"""

privacy_probe_strategy_format = """<STRATEGY>
Setup: What state and personal data will the probe create?
Probe Steps: Which HTTP requests, SQLite/file/log inspections, or deterministic state changes will the probe perform?
Violation Detection: What exact observable behavior or stored value indicates a violation of the selected PrivacyPatterns.org pattern?
Pass Condition: What exact observable behavior means no violation was detected?
Scenario Alignment: Why this probe does not contradict the scenario's allowed/forbidden data use or storage.
</STRATEGY>

If no viable deterministic privacy probe can be devised in the context of this scenario given the provided constraints, respond with `DISCARD` and write nothing else.
"""

privacy_code_format = """Make sure the privacy probe returns a set containing PrivacyPattern.{pattern_id} when it detects a violation, returns set() when no violation is detected, and returns None only when the probe cannot complete. Format the code as follows, keeping the given function signature:

<HEADER>
```python
# import other libraries
# additional helper code not given already
```
</HEADER>
<FUNCTION>
```python
def {func_name}(app: AppInstance) -> set[PrivacyPattern] | None:
    pass
```
</FUNCTION>

Do not import AppInstance, PrivacyPattern, or any of the provided privacy probe helper functions: they are already provided in the execution context and must not be imported again in the header. If you cannot implement this privacy probe in the context of this scenario, respond with `DISCARD` and write nothing else.

When inspecting SQLite through `download_db_from_docker`, use only the context-manager form: `with download_db_from_docker(app.container_id, app.env) as db_path:`. Do not wrap it in `list(...)`, iterate over it, assign its return value directly, or pass its return value as an iterable.
"""

fix_privacy_probe_code_format = """If the privacy probe can be fixed, output the fixed Python function. It must return {{PrivacyPattern.{pattern_id}}} when it detects a violation, return set() when no violation is detected, and return None only when the probe cannot complete. Do not reference any other PrivacyPattern enum value. Format the code as follows, keeping the function signature:
<FUNCTION>
```python
def {privacy_test_name}(app: AppInstance) -> set[PrivacyPattern] | None:
    pass
```
</FUNCTION>

When inspecting SQLite through `download_db_from_docker`, use only the context-manager form: `with download_db_from_docker(app.container_id, app.env) as db_path:`. Do not wrap it in `list(...)`, iterate over it, assign its return value directly, or pass its return value as an iterable.

Otherwise, if the privacy probe should be discarded, write the word `DISCARD`. In either case, follow the provided format and write nothing else."""
