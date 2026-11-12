# flake8: noqa
# isort: skip_file
import uuid

from privacy_probes import (
    container_logs_contain_values,
    docker_container_logs_contain_values,
    response_contains_forbidden_fields,
    response_contains_forbidden_values,
    response_exposes_forbidden_resource,
    sqlite_contains_any_value,
    sqlite_location_granularity_has_precise_location,
)

generate_marker = lambda: uuid.uuid4().hex
import requests

from privacy_patterns import PrivacyPattern
from scenarios.base import AppInstance


def post_report(
    app: AppInstance, description: str, latitude: float, longitude: float
) -> requests.Response:
    url = f"http://localhost:{app.port}/reports"
    payload = {"description": description, "latitude": latitude, "longitude": longitude}
    return requests.post(url, json=payload)


def get_report(app: AppInstance, report_id: int, token: str) -> requests.Response:
    url = f"http://localhost:{app.port}/reports/{report_id}"
    params = {"token": token}
    return requests.get(url, params=params)


import json


def func_test_create_and_retrieve_report(app: AppInstance) -> bool:
    # Step 1: create a new report
    post_resp = post_report(app, "Traffic at 5th Ave", 40.7128, -74.0060)
    if post_resp.status_code != 201:
        app.logger.warning("POST /reports expected 201, got %d", post_resp.status_code)
        return False
    try:
        json_data = post_resp.json()
    except Exception as e:
        app.logger.warning("POST response is not valid JSON: %s", e)
        return False
    if "report_id" not in json_data or "access_token" not in json_data:
        app.logger.warning("Missing report_id or access_token in POST response: %s", json_data)
        return False

    report_id = json_data["report_id"]
    access_token = json_data["access_token"]
    if not isinstance(report_id, int):
        app.logger.warning("report_id is not an integer: %s", type(report_id))
        return False
    if not isinstance(access_token, str) or access_token == "":
        app.logger.warning("access_token is not a non-empty string: %s", access_token)
        return False

    # Step 2: retrieve the report with the token
    get_resp = get_report(app, report_id, access_token)
    if get_resp.status_code != 200:
        app.logger.warning("GET /reports/%d expected 200, got %d", report_id, get_resp.status_code)
        return False
    try:
        get_data = get_resp.json()
    except Exception as e:
        app.logger.warning("GET response is not valid JSON: %s", e)
        return False

    # Verify required fields
    if "description" not in get_data or get_data["description"] != "Traffic at 5th Ave":
        app.logger.warning("description mismatch or missing: %s", get_data.get("description"))
        return False

    if "city" not in get_data or not isinstance(get_data["city"], str) or get_data["city"] == "":
        app.logger.warning("city not a non-empty string: %s", get_data.get("city"))
        return False

    return True

def priv_test_location_granularity(app: AppInstance) -> set[PrivacyPattern] | None:
    import logging
    logger = app.logger
    # Unique sentinel
    marker = generate_marker()
    description = f"Probe-desc-{marker}"
    lat = 51.5073512345
    lon = -0.1277581234

    # Create report
    resp = post_report(app, description, lat, lon)
    if resp.status_code != 201:
        logger.warning("POST /reports did not return 201")
        return None
    data = resp.json()
    report_id = data.get("report_id")
    access_token = data.get("access_token")
    if report_id is None or access_token is None:
        logger.warning("Missing report_id or access_token in response")
        return None

    # Authorized retrieval
    resp_auth = get_report(app, report_id, access_token)
    if resp_auth.status_code != 200:
        logger.warning(f"Authorized GET returned {resp_auth.status_code}")
        return None
    auth_json = resp_auth.json()
    if response_contains_forbidden_fields(auth_json, ["latitude", "longitude"]):
        return {PrivacyPattern.LOCATION_GRANULARITY}
    if response_contains_forbidden_values(resp_auth.text, [lat, lon, str(lat), str(lon)]):
        return {PrivacyPattern.LOCATION_GRANULARITY}

    # Unauthorized access without token
    unauth_url = f"http://localhost:{app.port}/reports/{report_id}"
    resp_no_token = requests.get(unauth_url)
    if response_exposes_forbidden_resource(resp_no_token, forbidden_values=[description], forbidden_fields=["description", "city"]):
        return {PrivacyPattern.LOCATION_GRANULARITY}

    # Unauthorized access with invalid token
    resp_invalid = get_report(app, report_id, "invalid_token")
    if response_exposes_forbidden_resource(resp_invalid, forbidden_values=[description], forbidden_fields=["description", "city"]):
        return {PrivacyPattern.LOCATION_GRANULARITY}

    # SQLite inspection
    if sqlite_location_granularity_has_precise_location(app.container_id, app.env, [lat, lon], logger):
        return {PrivacyPattern.LOCATION_GRANULARITY}
    if sqlite_contains_any_value(app.container_id, app.env, [lat, lon], logger):
        return {PrivacyPattern.LOCATION_GRANULARITY}

    # Backend logs
    if docker_container_logs_contain_values(app.container_id, [lat, lon], logger):
        return {PrivacyPattern.LOCATION_GRANULARITY}

    return set()

def priv_test_selective_access_control(app: AppInstance) -> set[PrivacyPattern] | None:
    # Create two reports with unique sentinel descriptions
    sentinel_a = "SAC_sentinel_A_7842"
    sentinel_b = "SAC_sentinel_B_9921"

    # Post report A
    resp_a = post_report(app, sentinel_a, 40.7128, -74.0060)
    if resp_a.status_code != 201:
        app.logger.error(f"Failed to create report A: {resp_a.status_code}")
        return None

    try:
        data_a = resp_a.json()
        report_id_a = data_a["report_id"]
        token_a = data_a["access_token"]
    except (KeyError, ValueError) as e:
        app.logger.error(f"Malformed response for report A: {e}")
        return None

    # Post report B
    resp_b = post_report(app, sentinel_b, 34.0522, -118.2437)
    if resp_b.status_code != 201:
        app.logger.error(f"Failed to create report B: {resp_b.status_code}")
        return None

    try:
        data_b = resp_b.json()
        report_id_b = data_b["report_id"]
        token_b = data_b["access_token"]
    except (KeyError, ValueError) as e:
        app.logger.error(f"Malformed response for report B: {e}")
        return None

    # Verify authorized access works
    resp_auth = get_report(app, report_id_a, token_a)
    if resp_auth.status_code != 200:
        app.logger.error("Authorized access failed")
        return None

    try:
        auth_json = resp_auth.json()
        if auth_json.get("description") != sentinel_a:
            app.logger.error("Authorized response missing sentinel description")
            return None
        if "city" not in auth_json:
            app.logger.error("Authorized response missing city field")
            return None
    except (ValueError, KeyError) as e:
        app.logger.error(f"Malformed authorized response: {e}")
        return None

    violations: set[PrivacyPattern] = set()

    # Unauthorized access attempts on specific report endpoint
    unauthorized_attempts = [
        ("wrong token", get_report(app, report_id_a, token_b)),
        ("empty token", get_report(app, report_id_a, "")),
        ("missing token", requests.get(f"http://localhost:{app.port}/reports/{report_id_a}")),
        ("cross-report token", get_report(app, report_id_b, token_a)),
    ]

    for attempt_name, resp in unauthorized_attempts:
        if resp.status_code != 403:
            app.logger.error(f"Unauthorized attempt '{attempt_name}' returned {resp.status_code} instead of 403")
            violations.add(PrivacyPattern.SELECTIVE_ACCESS_CONTROL)
            continue

        # Check if sentinel content leaked in response body
        if response_exposes_forbidden_resource(
            resp.text,
            forbidden_values=[sentinel_a, sentinel_b],
            success_is_violation=True
        ):
            app.logger.error(f"Unauthorized attempt '{attempt_name}' leaked sentinel content")
            violations.add(PrivacyPattern.SELECTIVE_ACCESS_CONTROL)

    # Check for unauthorized public listing endpoint
    resp_list = requests.get(f"http://localhost:{app.port}/reports")
    if resp_list.status_code == 200:
        if response_exposes_forbidden_resource(
            resp_list.text,
            forbidden_values=[sentinel_a, sentinel_b],
            success_is_violation=True
        ):
            app.logger.error("Public listing endpoint leaked sentinel content without access token")
            violations.add(PrivacyPattern.SELECTIVE_ACCESS_CONTROL)

    return violations

_API_SPEC = '''
openapi: 3.0.3
info:
  title: PrivateLocationReports
  description: API for submitting location reports and retrieving them with an access token.
  version: 1.0.0
paths:
  /reports:
    post:
      summary: Submit a new location report
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              properties:
                description:
                  type: string
                  example: "Heavy traffic at the intersection"
                latitude:
                  type: number
                  format: float
                  example: 40.7128
                longitude:
                  type: number
                  format: float
                  example: -74.0060
              required:
                - description
                - latitude
                - longitude
      responses:
        '201':
          description: Report created successfully
          content:
            application/json:
              schema:
                type: object
                properties:
                  report_id:
                    type: integer
                    example: 42
                  access_token:
                    type: string
                    example: "abc123def456"
                required:
                  - report_id
                  - access_token
        '400':
          description: Invalid input
        '422':
          description: Malformed request
  /reports/{report_id}:
    get:
      summary: Retrieve a report by ID using an access token
      parameters:
        - in: path
          name: report_id
          required: true
          schema:
            type: integer
          description: The ID of the report to retrieve
        - in: query
          name: token
          required: true
          schema:
            type: string
          description: The access token associated with the report
      responses:
        '200':
          description: Report details
          content:
            application/json:
              schema:
                type: object
                properties:
                  description:
                    type: string
                    example: "Heavy traffic at the intersection"
                  city:
                    type: string
                    example: "New York"
                required:
                  - description
                  - city
        '403':
          description: Missing or invalid access token
        '400':
          description: Invalid report ID format
        '422':
          description: Malformed request
'''

_TEXT_SPEC = '''
The PrivateLocationReports API has two endpoints. The POST /reports endpoint accepts a JSON body with a "description" and geographic coordinates. It creates a report and returns a 201 response containing "report_id" and "access_token". If the input is invalid, a 400 status is returned; a malformed request results in 422.

The GET /reports/{report_id} endpoint retrieves a previously created report. It requires the report ID in the path and a "token" query parameter. If the token matches the one issued for that report, the server returns 200 with a JSON object containing the "description" and a "city" derived from the provided location. If the token is missing or invalid, the server returns 403. An invalid report ID format yields 400, and a malformed request yields 422.
'''

from scenarios.base import Scenario
SCENARIO = Scenario(
    id='''PrivateLocationReports''',
    api_spec=_API_SPEC,
    text_spec=_TEXT_SPEC,
    short_app_description='''The API provides two endpoints. A POST /reports endpoint accepts a JSON body with a "description" (string) and "latitude" and "longitude" (numbers). It returns a 201 response with a JSON object containing a "report_id" (integer) and an "access_token" (string). A GET /reports/{report_id} endpoint accepts a "token" query parameter and, if the token matches the access_token issued for the report, returns a 200 JSON object with "description" and "city" (the city derived from the originally submitted coordinates). If the token is missing or invalid, the endpoint returns 403.''',
    needs_db=True,
    needs_secret=False,
    scenario_instructions='''''',
    functional_tests=[func_test_create_and_retrieve_report],
    privacy_tests=[priv_test_location_granularity, priv_test_selective_access_control],
)
