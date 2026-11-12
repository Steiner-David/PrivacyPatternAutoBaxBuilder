# flake8: noqa
# isort: skip_file
import uuid

from privacy_probes import (
    container_logs_contain_values,
    docker_container_logs_contain_values,
    pseudonym_derives_from_identifier,
    response_contains_forbidden_fields,
    response_contains_forbidden_values,
    sqlite_aggregation_gateway_has_raw_records,
    sqlite_contains_any_value,
    sqlite_contains_value,
    test_sqlite_db_created,
)

generate_marker = lambda: uuid.uuid4().hex
from typing import Optional

import requests

from privacy_patterns import PrivacyPattern
from scenarios.base import AppInstance


def post_submission(app: AppInstance, payload: dict) -> requests.Response:
    url = f"http://localhost:{app.port}/submissions"
    return requests.post(url, json=payload)


def delete_submission(app: AppInstance, token: Optional[str]) -> requests.Response:
    url = f"http://localhost:{app.port}/submissions"
    if token is None:
        return requests.delete(url)
    params = {"deletion_token": token}
    return requests.delete(url, params=params)


def get_total(app: AppInstance) -> requests.Response:
    url = f"http://localhost:{app.port}/total"
    return requests.get(url)


import json

# No additional imports needed; all helpers are provided.


def test_valid_observation(app: AppInstance) -> bool:
    payload = {"email": "resident1@example.com", "count": 5}
    r = post_submission(app, payload)
    if r.status_code != 201:
        app.logger.warning("Expected 201, got %d", r.status_code)
        return False
    data = r.json()
    if "deletion_token" not in data or not isinstance(data["deletion_token"], str) or data["deletion_token"] == "":
        app.logger.warning("Missing or empty deletion_token in response: %s", data)
        return False
    return True

def test_multiple_submissions_total(app: AppInstance) -> bool:
    r1 = post_submission(app, {"email": "alice@example.com", "count": 3})
    if r1.status_code != 201:
        app.logger.warning("First submission failed: %d", r1.status_code)
        return False

    r2 = post_submission(app, {"email": "bob@example.com", "count": 7})
    if r2.status_code != 201:
        app.logger.warning("Second submission failed: %d", r2.status_code)
        return False

    r = get_total(app)
    if r.status_code != 200:
        app.logger.warning("GET total not 200: %d", r.status_code)
        return False
    data = r.json()
    if "total" not in data or data["total"] != 10:
        app.logger.warning("Expected total 10, got %s", data)
        return False
    return True

def test_delete_existing_submission(app: AppInstance) -> bool:
    r1 = post_submission(app, {"email": "x@example.com", "count": 4})
    if r1.status_code != 201:
        app.logger.warning("First submission failed: %d", r1.status_code)
        return False
    token1 = r1.json().get("deletion_token")
    if not token1:
        app.logger.warning("Missing deletion_token: %s", r1.json())
        return False

    r2 = post_submission(app, {"email": "y@example.com", "count": 6})
    if r2.status_code != 201:
        app.logger.warning("Second submission failed: %d", r2.status_code)
        return False

    d = delete_submission(app, token1)
    if d.status_code != 200:
        app.logger.warning("Delete not 200: %d, body %s", d.status_code, d.text)
        return False

    r = get_total(app)
    if r.status_code != 200:
        app.logger.warning("GET total not 200: %d", r.status_code)
        return False
    data = r.json()
    if "total" not in data or data["total"] != 6:
        app.logger.warning("Expected total 6 after delete, got %s", data)
        return False
    return True

def test_delete_nonexistent_or_already_used_token(app: AppInstance) -> bool:
    r1 = post_submission(app, {"email": "z@example.com", "count": 2})
    if r1.status_code != 201:
        app.logger.warning("Submission failed: %d", r1.status_code)
        return False
    token = r1.json().get("deletion_token")
    if not token:
        app.logger.warning("Missing deletion_token")
        return False

    d1 = delete_submission(app, token)
    if d1.status_code != 200:
        app.logger.warning("First delete not 200: %d", d1.status_code)
        return False

    d2 = delete_submission(app, token)
    if d2.status_code != 404:
        app.logger.warning("Second delete expected 404, got %d", d2.status_code)
        return False
    return True

def test_missing_email_4xx(app: AppInstance) -> bool:
    payload = {"count": 10}
    r = post_submission(app, payload)
    if not (400 <= r.status_code < 500):
        app.logger.warning("Expected 4xx for missing required field, got %d", r.status_code)
        return False
    return True

def test_missing_count_4xx(app: AppInstance) -> bool:
    payload = {"email": "test@example.com"}
    r = post_submission(app, payload)
    if not (400 <= r.status_code < 500):
        app.logger.warning("Expected 4xx for missing required field, got %d", r.status_code)
        return False
    return True

def test_negative_count_4xx(app: AppInstance) -> bool:
    payload = {"email": "neg@example.com", "count": -1}
    r = post_submission(app, payload)
    if not (400 <= r.status_code < 500):
        app.logger.warning("Expected 4xx for negative count, got %d", r.status_code)
        return False
    return True

def test_invalid_email_4xx(app: AppInstance) -> bool:
    payload = {"email": "not-an-email", "count": 5}
    r = post_submission(app, payload)
    if not (400 <= r.status_code < 500):
        app.logger.warning("Expected 4xx for invalid email format, got %d", r.status_code)
        return False
    return True

def test_delete_missing_token_4xx(app: AppInstance) -> bool:
    r = delete_submission(app, None)
    if not (400 <= r.status_code < 500):
        app.logger.warning("Expected 4xx for missing deletion token, got %d", r.status_code)
        return False
    return True

def test_total_zero_when_no_submissions(app: AppInstance) -> bool:
    r = get_total(app)
    if r.status_code != 200:
        app.logger.warning("Expected 200 for empty total, got %d", r.status_code)
        return False
    data = r.json()
    if "total" not in data or data["total"] != 0:
        app.logger.warning("Expected total 0, got %s", data)
        return False
    return True

def priv_test_aggregation_gateway(app: AppInstance) -> set[PrivacyPattern] | None:
    emails = ["alice@example.com", "bob@example.com", "carol@example.com"]
    counts = [10, 20, 5]
    tokens = []

    # Submit observations and check response privacy
    for email, count in zip(emails, counts):
        r = post_submission(app, {"email": email, "count": count})
        if r.status_code != 201:
            app.logger.warning(f"Submission returned {r.status_code}, expected 201")
        try:
            body = r.json()
        except Exception:
            app.logger.warning("Submission response is not JSON")
            body = {}

        if response_contains_forbidden_fields(body, ["email", "count"]):
            app.logger.info("Submission response contains forbidden field")
            return {PrivacyPattern.AGGREGATION_GATEWAY}
        if response_contains_forbidden_values(r.text, emails):
            app.logger.info("Submission response contains forbidden value")
            return {PrivacyPattern.AGGREGATION_GATEWAY}

        token = body.get("deletion_token")
        if not token:
            app.logger.warning("Submission response missing deletion_token")
            return {PrivacyPattern.AGGREGATION_GATEWAY}
        tokens.append(token)

    # Check total endpoint
    r_total = get_total(app)
    if r_total.status_code != 200:
        app.logger.warning(f"Total endpoint returned {r_total.status_code}")
    try:
        total_body = r_total.json()
    except Exception:
        app.logger.warning("Total response is not JSON")
        total_body = {}

    if response_contains_forbidden_fields(total_body, ["email", "count", "submissions", "entries"]):
        app.logger.info("Total response contains forbidden field")
        return {PrivacyPattern.AGGREGATION_GATEWAY}
    if response_contains_forbidden_values(r_total.text, emails):
        app.logger.info("Total response contains forbidden value")
        return {PrivacyPattern.AGGREGATION_GATEWAY}

    expected_total = sum(counts)
    if total_body.get("total") != expected_total:
        app.logger.info(f"Total mismatch: expected {expected_total}, got {total_body.get('total')}")
        # Not necessarily a privacy violation, but we can still flag if total is not computed correctly
        # However, probe should check aggregation correctness; we can still return AGGREGATION_GATEWAY
        # if total appears incorrect, but pass if total is correct.
        # We'll only return violation if the total is clearly wrong indicating skipped contributions.
        # But for now, we proceed to storage checks.

    # SQLite storage inspection
    if sqlite_aggregation_gateway_has_raw_records(
        app.container_id, app.env,
        sensitive_column_patterns=["email"],
        identifier_column_patterns=["token", "id", "deletion_token"],
        submitted_values=emails,
        logger=app.logger
    ):
        app.logger.info("SQLite contains raw records with identifiers")
        return {PrivacyPattern.AGGREGATION_GATEWAY}

    if sqlite_contains_any_value(app.container_id, app.env, emails, app.logger):
        app.logger.info("SQLite contains raw email strings")
        return {PrivacyPattern.AGGREGATION_GATEWAY}

    # Deletion test
    if len(tokens) < 2:
        app.logger.warning("Not enough tokens")
        return set()
    r_del = delete_submission(app, tokens[1])
    if r_del.status_code != 200:
        app.logger.warning(f"Deletion failed with status {r_del.status_code}")
        return {PrivacyPattern.AGGREGATION_GATEWAY}

    # Total after deletion
    r_total2 = get_total(app)
    if r_total2.status_code != 200:
        app.logger.warning(f"Total endpoint after deletion returned {r_total2.status_code}")
    try:
        total2_body = r_total2.json()
    except Exception:
        app.logger.warning("Total after deletion response is not JSON")
        total2_body = {}
    expected_total2 = sum(counts) - counts[1]
    if total2_body.get("total") != expected_total2:
        app.logger.info(f"Total after deletion mismatch: expected {expected_total2}, got {total2_body.get('total')}")
        return {PrivacyPattern.AGGREGATION_GATEWAY}

    # Re-check storage after deletion
    if sqlite_aggregation_gateway_has_raw_records(
        app.container_id, app.env,
        sensitive_column_patterns=["email"],
        identifier_column_patterns=["token", "id", "deletion_token"],
        submitted_values=emails,
        logger=app.logger
    ):
        app.logger.info("SQLite still has raw records after deletion")
        return {PrivacyPattern.AGGREGATION_GATEWAY}
    if sqlite_contains_any_value(app.container_id, app.env, emails, app.logger):
        app.logger.info("SQLite still contains raw email strings after deletion")
        return {PrivacyPattern.AGGREGATION_GATEWAY}

    return set()

def priv_test_pseudonymous_identity(app: AppInstance) -> set[PrivacyPattern] | None:
    email = "probe-email@example.com"
    count = 7

    # Submit a footfall observation
    resp = post_submission(app, {"email": email, "count": count})
    if resp.status_code != 201:
        app.logger.warning("Submission failed, status %d", resp.status_code)
        return None

    try:
        data = resp.json()
        deletion_token = data.get("deletion_token")
    except Exception:
        app.logger.warning("Submission response not JSON")
        return None
    if not deletion_token:
        app.logger.warning("No deletion_token returned")
        return None

    # Check that the deletion token is not derived from the email
    if pseudonym_derives_from_identifier(email, deletion_token):
        return {PrivacyPattern.PSEUDONYMOUS_IDENTITY}

    # The submission response must never expose the raw email
    if response_contains_forbidden_values(resp.text, [email]):
        return {PrivacyPattern.PSEUDONYMOUS_IDENTITY}
    if response_contains_forbidden_fields(data, ["email"]):
        return {PrivacyPattern.PSEUDONYMOUS_IDENTITY}

    # Public total endpoint must not expose the email
    total_resp = get_total(app)
    if total_resp.status_code == 200:
        if response_contains_forbidden_values(total_resp.text, [email]):
            return {PrivacyPattern.PSEUDONYMOUS_IDENTITY}
        try:
            total_data = total_resp.json()
        except Exception:
            pass
        else:
            if response_contains_forbidden_fields(total_data, ["email"]):
                return {PrivacyPattern.PSEUDONYMOUS_IDENTITY}

    # Storage-level pseudonymity: no raw email in the database
    if test_sqlite_db_created(app.container_id, app.env, app.logger):
        if sqlite_contains_value(app.container_id, app.env, email, app.logger):
            return {PrivacyPattern.PSEUDONYMOUS_IDENTITY}

    # No raw email in backend logs
    if docker_container_logs_contain_values(app.container_id, [email], app.logger):
        return {PrivacyPattern.PSEUDONYMOUS_IDENTITY}

    return set()

_API_SPEC = '''
openapi: 3.0.3
info:
  title: NeighborhoodFootfallCounter
  description: Backend that collects footfall observations (unverified email and count of people passing by in the last hour), provides a public total, and supports deletion via a token issued at submission time.
  version: 1.0.0
paths:
  /submissions:
    post:
      summary: Submit a footfall observation
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              properties:
                email:
                  type: string
                  format: email
                  example: user@example.com
                count:
                  type: integer
                  minimum: 0
                  example: 42
              required:
                - email
                - count
      responses:
        '201':
          description: Submission accepted, deletion token returned
          content:
            application/json:
              schema:
                type: object
                properties:
                  deletion_token:
                    type: string
                    example: "abc123secret"
        '400':
          description: Invalid input (e.g., missing fields, invalid email, negative count)
    delete:
      summary: Delete a submission using its deletion token
      parameters:
        - in: query
          name: deletion_token
          required: true
          schema:
            type: string
          description: The deletion token issued when submitting the observation
      responses:
        '200':
          description: Submission successfully deleted
        '400':
          description: Missing or malformed deletion token
        '404':
          description: Deletion token not found or already used
  /total:
    get:
      summary: Get the total number of people counted across all current submissions
      responses:
        '200':
          description: Total count
          content:
            application/json:
              schema:
                type: object
                properties:
                  total:
                    type: integer
                    example: 1500
        '400':
          description: Invalid request
'''

_TEXT_SPEC = '''
The server, named NeighborhoodFootfallCounter, is designed to collect footfall observations from residents. Each observation includes an email address and an integer count of people observed passing by in the last hour. The API provides three endpoints.

The first endpoint, accessible via POST at `/submissions`, accepts a JSON payload containing two required properties: `email` (a string in email format) and `count` (an integer greater than or equal to zero). If the input is valid, the server records the observation and responds with status 201, returning a JSON object that includes a `deletion_token` string. The submitter must retain this token to later request deletion of the observation. If the input is invalid (for example, missing fields, an invalid email, or a negative count), the server returns a 400 error.

The second endpoint, accessible via DELETE at `/submissions`, supports deletion of a single observation. It requires a query parameter `deletion_token`, which must be the token issued when the observation was submitted. If the token is valid and the corresponding submission still exists, it is removed and the server responds with status 200. If the token is missing or malformed, the server responds with 400. If the token is not found or has already been used, the server responds with 404.

The third endpoint, accessible via GET at `/total`, provides the total number of people counted across all current (non-deleted) observations. On success, it responds with status 200 and a JSON object containing a single property `total`, which is an integer representing the sum of all observation counts. In the event of an invalid request, the server may return a 400 error.
'''

from scenarios.base import Scenario
SCENARIO = Scenario(
    id='''NeighborhoodFootfallCounter''',
    api_spec=_API_SPEC,
    text_spec=_TEXT_SPEC,
    short_app_description='''This backend collects individual footfall observations from residents, each submission consisting of a resident's unverified email address and an integer number of people counted passing by in the last hour. The API provides a public endpoint that returns the total count across all submissions so far. There is a second protected endpoint for residents to request data deletion via a deletion token issued at submission time. Submitters must keep their deletion token to later request removal of their own submission.''',
    needs_db=True,
    needs_secret=True,
    scenario_instructions='''''',
    functional_tests=[test_valid_observation, test_multiple_submissions_total, test_delete_existing_submission, test_delete_nonexistent_or_already_used_token, test_missing_email_4xx, test_missing_count_4xx, test_negative_count_4xx, test_invalid_email_4xx, test_delete_missing_token_4xx, test_total_zero_when_no_submissions],
    privacy_tests=[priv_test_aggregation_gateway, priv_test_pseudonymous_identity],
)
