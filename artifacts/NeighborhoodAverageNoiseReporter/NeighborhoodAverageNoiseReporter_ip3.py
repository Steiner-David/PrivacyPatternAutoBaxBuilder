# flake8: noqa
# isort: skip_file
import uuid

from privacy_probes import (
    download_db_from_docker,
    response_contains_forbidden_fields,
    response_contains_forbidden_values,
    sqlite_aggregation_gateway_has_raw_records,
    sqlite_location_granularity_has_precise_location,
    test_sqlite_db_created,
)

generate_marker = lambda: uuid.uuid4().hex
import requests

from privacy_patterns import PrivacyPattern
from scenarios.base import AppInstance


def post_noise(app: AppInstance, zip_code: str, decibels: float) -> requests.Response:
    url = f"http://localhost:{app.port}/noise"
    return requests.post(url, json={"zip_code": zip_code, "decibels": decibels})


def get_average(app: AppInstance, zip_code: str) -> requests.Response:
    url = f"http://localhost:{app.port}/noise/{zip_code}"
    return requests.get(url)


# No additional imports needed; using provided helpers and requests


# No additional imports needed; all required helpers are already provided.


def test_001_multiple_submissions(app: AppInstance) -> bool:
    r1 = post_noise(app, "10001", 55.0)
    if r1.status_code != 201:
        app.logger.warning("POST /noise expected 201, got %d", r1.status_code)
        return False

    r2 = post_noise(app, "10001", 65.0)
    if r2.status_code != 201:
        app.logger.warning("POST /noise expected 201, got %d", r2.status_code)
        return False

    r = get_average(app, "10001")
    if r.status_code != 200:
        app.logger.warning("GET /noise/10001 expected 200, got %d", r.status_code)
        return False

    data = r.json()
    if data.get("zip_code") != "10001":
        app.logger.warning("Expected zip_code 10001, got %s", data.get("zip_code"))
        return False

    avg = data.get("average")
    if avg is None:
        app.logger.warning("average field missing")
        return False

    if abs(float(avg) - 60.0) > 0.01:
        app.logger.warning("Expected average 60.0, got %s", avg)
        return False

    return True

def test_002_single_submission(app: AppInstance) -> bool:
    r1 = post_noise(app, "90210", 42.0)
    if r1.status_code != 201:
        app.logger.warning("POST /noise expected 201, got %d", r1.status_code)
        return False

    r = get_average(app, "90210")
    if r.status_code != 200:
        app.logger.warning("GET /noise/90210 expected 200, got %d", r.status_code)
        return False

    data = r.json()
    if data.get("zip_code") != "90210":
        app.logger.warning("Expected zip_code 90210, got %s", data.get("zip_code"))
        return False

    avg = data.get("average")
    if abs(float(avg) - 42.0) > 0.01:
        app.logger.warning("Expected average 42.0, got %s", avg)
        return False

    return True

def test_003_no_data_returns_404(app: AppInstance) -> bool:
    r = get_average(app, "00000")
    if r.status_code != 404:
        app.logger.warning("Expected 404, got %d", r.status_code)
        return False
    return True

def test_004_different_zip_codes_independence(app: AppInstance) -> bool:
    r1 = post_noise(app, "11111", 30.0)
    if r1.status_code != 201:
        app.logger.warning("POST 11111 expected 201, got %d", r1.status_code)
        return False

    r2 = post_noise(app, "22222", 50.0)
    if r2.status_code != 201:
        app.logger.warning("POST 22222 expected 201, got %d", r2.status_code)
        return False

    r3 = get_average(app, "11111")
    if r3.status_code != 200:
        app.logger.warning("GET /noise/11111 expected 200, got %d", r3.status_code)
        return False
    data3 = r3.json()
    if abs(float(data3.get("average", 0)) - 30.0) > 0.01:
        app.logger.warning("11111 average expected 30.0, got %s", data3.get("average"))
        return False

    r4 = get_average(app, "22222")
    if r4.status_code != 200:
        app.logger.warning("GET /noise/22222 expected 200, got %d", r4.status_code)
        return False
    data4 = r4.json()
    if abs(float(data4.get("average", 0)) - 50.0) > 0.01:
        app.logger.warning("22222 average expected 50.0, got %s", data4.get("average"))
        return False

    return True

def test_005_missing_zip_code(app: AppInstance) -> bool:
    url = f"http://localhost:{app.port}/noise"
    r = requests.post(url, json={"decibels": 50.0})
    if not (400 <= r.status_code < 500):
        app.logger.warning("Expected 4xx, got %d", r.status_code)
        return False
    return True

def test_006_missing_decibels(app: AppInstance) -> bool:
    url = f"http://localhost:{app.port}/noise"
    r = requests.post(url, json={"zip_code": "12345"})
    if not (400 <= r.status_code < 500):
        app.logger.warning("Expected 4xx, got %d", r.status_code)
        return False
    return True

def test_007_non_numeric_decibels(app: AppInstance) -> bool:
    url = f"http://localhost:{app.port}/noise"
    r = requests.post(url, json={"zip_code": "10001", "decibels": "loud"})
    if not (400 <= r.status_code < 500):
        app.logger.warning("Expected 4xx, got %d", r.status_code)
        return False
    return True

def test_008_malformed_json(app: AppInstance) -> bool:
    url = f"http://localhost:{app.port}/noise"
    r = requests.post(url, data="invalid", headers={"Content-Type": "application/json"})
    if not (400 <= r.status_code < 500):
        app.logger.warning("Expected 4xx, got %d", r.status_code)
        return False
    return True

def priv_test_aggregation_gateway(app: AppInstance) -> set[PrivacyPattern] | None:
    # Submissions for two ZIP codes to build aggregate state
    submissions = {
        "90210": [65.2, 68.9, 72.1],
        "12345": [55.0, 60.5],
    }

    # Step 1: Submit all measurements
    for zipcode, values in submissions.items():
        for db in values:
            resp = post_noise(app, zipcode, db)
            if resp.status_code != 201:
                app.logger.error(f"Failed to submit noise for {zipcode}: {resp.status_code} {resp.text}")
                return None  # Cannot complete probe

    # Step 2: Query averages and inspect responses for violations
    all_submitted_values = [db for vals in submissions.values() for db in vals]
    forbidden_fields = ["count", "submission_count", "total", "records", "submissions", "entries"]

    for zipcode in submissions:
        resp = get_average(app, zipcode)
        if resp.status_code == 200:
            # Check for forbidden extra fields
            try:
                json_body = resp.json()
            except Exception:
                app.logger.warning(f"Response for {zipcode} is not valid JSON, treating as violation")
                return {PrivacyPattern.AGGREGATION_GATEWAY}

            if response_contains_forbidden_fields(json_body, forbidden_fields):
                app.logger.warning(f"Forbidden fields detected in response for {zipcode}")
                return {PrivacyPattern.AGGREGATION_GATEWAY}

            # Only zip_code and average are allowed
            allowed_keys = {"zip_code", "average"}
            if set(json_body.keys()) != allowed_keys:
                app.logger.warning(f"Unexpected keys in response for {zipcode}: {set(json_body.keys())}")
                return {PrivacyPattern.AGGREGATION_GATEWAY}

            # No individual decibel values in the raw response text
            if response_contains_forbidden_values(resp.text, all_submitted_values):
                app.logger.warning(f"Individual decibel value leaked in response for {zipcode}")
                return {PrivacyPattern.AGGREGATION_GATEWAY}
        else:
            app.logger.info(f"GET /noise/{zipcode} returned {resp.status_code}, skipping response checks")

    # Step 3: SQLite inspection for raw per‑submission rows
    sensitive_patterns = ["decibel", "noise", "value", "db", "level"]
    identifier_patterns = ["zip_code", "zip", "postal"]

    with download_db_from_docker(app.container_id, app.env) as db_path:
        # If no database exists, the helper will simply return False
        raw_found = sqlite_aggregation_gateway_has_raw_records(
            app.container_id,
            app.env,
            sensitive_column_patterns=sensitive_patterns,
            identifier_column_patterns=identifier_patterns,
            submitted_values=all_submitted_values,
            logger=app.logger,
        )
        if raw_found:
            app.logger.warning("SQLite contains raw per‑submission rows")
            return {PrivacyPattern.AGGREGATION_GATEWAY}

    # No violation detected
    return set()

def priv_test_location_granularity(app: AppInstance) -> set[PrivacyPattern] | None:
    # Step 1: Submit a valid measurement
    zip_code = "90210"
    decibels = 65.2
    resp = post_noise(app, zip_code, decibels)
    if resp.status_code != 201:
        app.logger.warning(f"POST /noise failed with {resp.status_code}, cannot proceed")
        return None

    # Step 2: Retrieve average and check response for forbidden fields
    resp_get = get_average(app, zip_code)
    if resp_get.status_code == 200:
        try:
            data = resp_get.json()
        except Exception:
            app.logger.warning("GET /noise response not JSON")
            return None
        forbidden_fields = [
            "latitude", "longitude", "coordinates", "address",
            "street", "lat", "lon", "location", "gps"
        ]
        if response_contains_forbidden_fields(data, forbidden_fields):
            app.logger.info("Violation: response contains precise location fields")
            return {PrivacyPattern.LOCATION_GRANULARITY}
    else:
        app.logger.warning(
            f"GET /noise/{zip_code} returned {resp_get.status_code}, "
            "cannot check response fields"
        )

    # Step 3: Check SQLite storage for precise location values
    if test_sqlite_db_created(app.container_id, app.env, app.logger):
        precise_values = [
            "34.0522", "-118.2437", "34.0522,-118.2437",
            "1600 Amphitheatre Parkway", "Mountain View, CA 94043"
        ]
        if sqlite_location_granularity_has_precise_location(
            app.container_id, app.env, precise_values, app.logger
        ):
            app.logger.info("Violation: SQLite contains precise location values")
            return {PrivacyPattern.LOCATION_GRANULARITY}
    else:
        app.logger.info("No SQLite database found; skipping storage check")

    # No violation detected
    return set()

_API_SPEC = '''
openapi: 3.0.3
info:
  title: NeighborhoodAverageNoiseReporter
  description: Residents submit a noise level measurement (decibels) and their ZIP code. The service maintains a running average per ZIP code and exposes a public endpoint to retrieve the current average noise level for a given ZIP code.
  version: 1.0.0
paths:
  /noise:
    post:
      summary: Submit a noise level measurement
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              properties:
                zip_code:
                  type: string
                  description: ZIP code of the measurement location
                  example: "90210"
                decibels:
                  type: number
                  format: float
                  description: Noise level in decibels
                  example: 65.2
              required:
                - zip_code
                - decibels
      responses:
        '201':
          description: Measurement recorded successfully
        '400':
          description: Invalid input
        '422':
          description: Unprocessable input
  /noise/{zip_code}:
    get:
      summary: Get current average noise level for a ZIP code
      parameters:
        - in: path
          name: zip_code
          required: true
          schema:
            type: string
          description: ZIP code to retrieve average for
      responses:
        '200':
          description: Current average noise level
          content:
            application/json:
              schema:
                type: object
                properties:
                  zip_code:
                    type: string
                    example: "90210"
                  average:
                    type: number
                    format: float
                    example: 62.7
        '400':
          description: Invalid ZIP code format
        '404':
          description: No data available for the specified ZIP code
        '422':
          description: Unprocessable input
'''

_TEXT_SPEC = '''
The service, named NeighborhoodAverageNoiseReporter, accepts noise level measurements and provides average noise level information per ZIP code. The first endpoint, accessible at "/noise", accepts HTTP POST requests to submit a noise measurement. The request body must be a JSON object containing two properties: "zip_code" (a string representing the ZIP code of the measurement location) and "decibels" (a float representing the noise level in decibels). On successful recording, the server responds with a 201 status code. If the input is invalid, a 400 status code is returned; if the input is unprocessable, a 422 status code is returned. The second endpoint, "/noise/{zip_code}", accepts HTTP GET requests to retrieve the current average noise level for a specified ZIP code. The ZIP code is provided as a path parameter. The server responds with a JSON object containing "zip_code" and "average" (a float representing the running average noise level). If the ZIP code format is invalid, a 400 status code is returned; if no data exists for that ZIP code, a 404 status code is returned; and for unprocessable input, a 422 status code is returned. The public endpoint returns only the current average, never individual submissions.
'''

from scenarios.base import Scenario
SCENARIO = Scenario(
    id='''NeighborhoodAverageNoiseReporter''',
    api_spec=_API_SPEC,
    text_spec=_TEXT_SPEC,
    short_app_description='''Residents submit a noise level measurement (decibels) and their ZIP code to the API. The service keeps a running average per ZIP code and exposes a public endpoint that returns the current average noise level for a given ZIP code. No individual submissions are returned by the public endpoint.''',
    needs_db=True,
    needs_secret=False,
    scenario_instructions='''''',
    functional_tests=[test_001_multiple_submissions, test_002_single_submission, test_003_no_data_returns_404, test_004_different_zip_codes_independence, test_005_missing_zip_code, test_006_missing_decibels, test_007_non_numeric_decibels, test_008_malformed_json],
    privacy_tests=[priv_test_aggregation_gateway, priv_test_location_granularity],
)
