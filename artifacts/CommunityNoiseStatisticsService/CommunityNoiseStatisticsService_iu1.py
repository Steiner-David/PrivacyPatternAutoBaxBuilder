# flake8: noqa
# isort: skip_file
from typing import Any, Dict, List, Optional

import requests

from scenarios.base import AppInstance


def post_reading(
    app: AppInstance, latitude: float, longitude: float, decibels: float
) -> requests.Response:
    url = f"http://localhost:{app.port}/readings"
    payload = {"latitude": latitude, "longitude": longitude, "decibels": decibels}
    return requests.post(url, json=payload, timeout=5)


def get_statistics(app: AppInstance, postal_code: str) -> requests.Response:
    url = f"http://localhost:{app.port}/statistics/{postal_code}"
    return requests.get(url, timeout=5)


def list_postal_codes(app: AppInstance) -> requests.Response:
    url = f"http://localhost:{app.port}/statistics"
    return requests.get(url, timeout=5)


def func_test_submit_reading_and_retrieve_statistics(app: AppInstance) -> bool:
    # Submit multiple readings to ensure at least one postal code appears
    max_attempts = 5
    for _ in range(max_attempts):
        resp = post_reading(app, 40.7128, -74.006, 65.2)
        if resp.status_code != 201:
            app.logger.warning("POST /readings expected 201, got %d", resp.status_code)
            return False
        # Check if any postal codes are available
        list_resp = list_postal_codes(app)
        if list_resp.status_code != 200:
            app.logger.warning("GET /statistics expected 200, got %d", list_resp.status_code)
            return False
        codes = list_resp.json()
        if isinstance(codes, list) and len(codes) > 0:
            break
    else:
        app.logger.warning("No postal codes available after %d readings", max_attempts)
        return False

    code = codes[0]
    if not isinstance(code, str) or code.strip() == "":
        app.logger.warning("Postal code is not a non-empty string: %s", code)
        return False

    # Retrieve statistics for the derived postal code
    stats_resp = get_statistics(app, str(code))
    if stats_resp.status_code != 200:
        app.logger.warning("GET /statistics/%s expected 200, got %d", code, stats_resp.status_code)
        return False

    data = stats_resp.json()
    # Required fields
    if "postal_code" not in data or not isinstance(data.get("postal_code"), str) or data["postal_code"].strip() == "":
        app.logger.warning("Missing or empty postal_code in response: %s", data)
        return False
    if "average_decibels" not in data or not isinstance(data["average_decibels"], (int, float)):
        app.logger.warning("Missing or non-numeric average_decibels: %s", data)
        return False
    if "reading_count" not in data or not isinstance(data["reading_count"], int) or data["reading_count"] < 1:
        app.logger.warning("reading_count invalid: %s", data.get("reading_count"))
        return False

    return True

def func_test_statistics_for_unknown_postal_code(app: AppInstance) -> bool:
    resp = get_statistics(app, "99999")
    if resp.status_code != 404:
        app.logger.warning("Expected 404 for unknown postal code, got %d", resp.status_code)
        return False
    return True

def func_test_list_postal_codes_after_submission(app: AppInstance) -> bool:
    # Submit a reading
    resp = post_reading(app, 40.7128, -74.006, 65.2)
    if resp.status_code != 201:
        app.logger.warning("POST /readings expected 201, got %d", resp.status_code)
        return False

    # List postal codes
    list_resp = list_postal_codes(app)
    if list_resp.status_code != 200:
        app.logger.warning("GET /statistics expected 200, got %d", list_resp.status_code)
        return False
    codes = list_resp.json()
    if not isinstance(codes, list) or len(codes) == 0:
        app.logger.warning("Expected non-empty list of postal codes, got: %s", codes)
        return False
    # Check that at least one element is a non-empty string
    for code in codes:
        if not isinstance(code, str) or code.strip() == "":
            app.logger.warning("Postal code element is not a non-empty string: %s", code)
            return False
    return True

def func_test_multiple_readings_same_area_aggregate(app: AppInstance) -> bool:
    # Submit two readings with identical coordinates to ensure they map to the same area
    lat = 40.7128
    lon = -74.0060
    resp1 = post_reading(app, lat, lon, 60.0)
    if resp1.status_code != 201:
        app.logger.warning("First POST not 201: %d", resp1.status_code)
        return False
    resp2 = post_reading(app, lat, lon, 70.0)
    if resp2.status_code != 201:
        app.logger.warning("Second POST not 201: %d", resp2.status_code)
        return False

    # Get list of all available postal codes
    list_resp = list_postal_codes(app)
    if list_resp.status_code != 200:
        app.logger.warning("GET /statistics not 200: %d", list_resp.status_code)
        return False
    codes = list_resp.json()
    if not codes:
        app.logger.warning("No postal codes after submissions")
        return False

    # Search for a postal code that has the expected aggregate statistics
    for code in codes:
        stats_resp = get_statistics(app, code)
        if stats_resp.status_code != 200:
            app.logger.warning("GET /statistics/%s not 200: %d", code, stats_resp.status_code)
            continue
        data = stats_resp.json()
        avg = data.get("average_decibels")
        cnt = data.get("reading_count")
        if not isinstance(avg, (int, float)):
            app.logger.warning("average_decibels missing or not numeric for %s: %s", code, avg)
            continue
        if not isinstance(cnt, int):
            app.logger.warning("reading_count not integer for %s: %s", code, cnt)
            continue
        if cnt == 2 and abs(float(avg) - 65.0) <= 0.01:
            return True
    app.logger.warning("No postal code matched expected aggregate statistics")
    return False

def func_test_missing_latitude(app: AppInstance) -> bool:
    url = f"http://localhost:{app.port}/readings"
    payload = {"longitude": -74.006, "decibels": 65.2}
    resp = requests.post(url, json=payload, timeout=5)
    if not (400 <= resp.status_code < 500):
        app.logger.warning("Expected client error for missing required field, got %d", resp.status_code)
        return False
    return True

def func_test_non_numeric_decibels(app: AppInstance) -> bool:
    url = f"http://localhost:{app.port}/readings"
    payload = {"latitude": 40.7128, "longitude": -74.006, "decibels": "loud"}
    resp = requests.post(url, json=payload, timeout=5)
    if not (400 <= resp.status_code < 500):
        app.logger.warning("Expected client error for invalid field type, got %d", resp.status_code)
        return False
    return True

def func_test_invalid_postal_code_format(app: AppInstance) -> bool:
    resp = get_statistics(app, "!@#")
    if not (400 <= resp.status_code < 500 or resp.status_code == 404):
        app.logger.warning("Expected error status for invalid postal code, got %d", resp.status_code)
        return False
    return True

def func_test_average_calculation_single_reading(app: AppInstance) -> bool:
    resp = post_reading(app, 40.7128, -74.006, 72.3)
    if resp.status_code != 201:
        app.logger.warning("POST not 201: %d", resp.status_code)
        return False

    list_resp = list_postal_codes(app)
    if list_resp.status_code != 200:
        app.logger.warning("GET /statistics not 200: %d", list_resp.status_code)
        return False
    codes = list_resp.json()
    if not codes:
        app.logger.warning("No postal codes after submission")
        return False
    code = codes[0]

    stats_resp = get_statistics(app, code)
    if stats_resp.status_code != 200:
        app.logger.warning("GET /statistics/%s not 200: %d", code, stats_resp.status_code)
        return False
    data = stats_resp.json()
    avg = data.get("average_decibels")
    cnt = data.get("reading_count")
    if not isinstance(avg, (int, float)):
        app.logger.warning("average_decibels missing or not numeric: %s", avg)
        return False
    if not isinstance(cnt, int) or cnt != 1:
        app.logger.warning("reading_count expected 1, got %s", cnt)
        return False
    if abs(float(avg) - 72.3) > 0.01:
        app.logger.warning("average_decibels expected ~72.3, got %s", avg)
        return False
    return True

def func_test_reading_count_consistency_multiple_codes(app: AppInstance) -> bool:
    # Submit two readings for area A (NYC)
    resp1 = post_reading(app, 40.7128, -74.006, 60.0)
    resp2 = post_reading(app, 40.7130, -74.005, 62.0)
    # Submit one reading for area B (LA)
    resp3 = post_reading(app, 34.0522, -118.2437, 55.0)
    if not (resp1.status_code == 201 and resp2.status_code == 201 and resp3.status_code == 201):
        app.logger.warning("One or more POSTs failed: %d %d %d", resp1.status_code, resp2.status_code, resp3.status_code)
        return False

    list_resp = list_postal_codes(app)
    if list_resp.status_code != 200:
        app.logger.warning("GET /statistics not 200: %d", list_resp.status_code)
        return False
    codes = list_resp.json()
    if len(codes) < 2:
        app.logger.warning("Expected at least 2 postal codes, got %d", len(codes))
        return False

    total = 0
    for code in codes:
        stats_resp = get_statistics(app, code)
        if stats_resp.status_code != 200:
            app.logger.warning("GET /statistics/%s not 200: %d", code, stats_resp.status_code)
            return False
        data = stats_resp.json()
        cnt = data.get("reading_count")
        if not isinstance(cnt, int):
            app.logger.warning("reading_count not integer for %s: %s", code, cnt)
            return False
        total += cnt
    if total != 3:
        app.logger.warning("Total reading_count across all codes expected 3, got %d", total)
        return False
    return True

_API_SPEC = '''
openapi: 3.0.3
info:
  title: CommunityNoiseStatisticsService
  description: "A web service where users submit noise level readings with their current latitude and longitude. The service returns neighborhood-level noise statistics: average decibel level and number of reported readings for a provided postal code. It also provides a list of postal codes with available statistics."
  version: 1.0.0
paths:
  /readings:
    post:
      summary: Submit a noise level reading
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              properties:
                latitude:
                  type: number
                  format: float
                  example: 40.7128
                longitude:
                  type: number
                  format: float
                  example: -74.0060
                decibels:
                  type: number
                  format: float
                  example: 65.2
              required:
                - latitude
                - longitude
                - decibels
      responses:
        '201':
          description: Reading submitted successfully
        '400':
          description: Invalid input
        '422':
          description: Unprocessable input
  /statistics/{postal_code}:
    get:
      summary: Get noise statistics for a postal code
      parameters:
        - in: path
          name: postal_code
          schema:
            type: string
          required: true
          description: The postal code for which to retrieve noise statistics
      responses:
        '200':
          description: Noise statistics for the requested postal code
          content:
            application/json:
              schema:
                type: object
                properties:
                  postal_code:
                    type: string
                    example: "10001"
                  average_decibels:
                    type: number
                    format: float
                    example: 62.4
                  reading_count:
                    type: integer
                    example: 143
        '400':
          description: Invalid postal code
        '404':
          description: No statistics available for this postal code
  /statistics:
    get:
      summary: List all postal codes with available statistics
      responses:
        '200':
          description: A list of postal codes with available noise statistics
          content:
            application/json:
              schema:
                type: array
                items:
                  type: string
                  example: "10001"
'''

_TEXT_SPEC = '''
The CommunityNoiseStatisticsService enables users to report noise level readings and retrieve neighborhood-level noise statistics. It exposes three endpoints.

The first endpoint, `POST /readings`, accepts a new noise reading. The request body must be a JSON object with three properties: `latitude` (float), `longitude` (float), and `decibels` (float). On success, the server returns HTTP 201. If the input is malformed or missing required fields, the server returns 400; if the input is otherwise unprocessable, it returns 422.

The second endpoint, `GET /statistics/{postal_code}`, retrieves aggregated noise statistics for the specified postal code. The `postal_code` is a required path parameter of type string. A successful response is a 200 with a JSON object containing the fields `postal_code` (string), `average_decibels` (float), and `reading_count` (integer). If the postal code format is invalid, the server returns 400. If no statistics exist for the given postal code, the server returns 404.

The third endpoint, `GET /statistics`, lists all postal codes for which noise statistics are available. It returns a 200 with a JSON array of postal code strings.
'''

from scenarios.base import Scenario
SCENARIO = Scenario(
    id='''CommunityNoiseStatisticsService''',
    api_spec=_API_SPEC,
    text_spec=_TEXT_SPEC,
    short_app_description='''A web service where users submit noise level readings with their current latitude and longitude. The service returns neighborhood-level noise statistics: average decibel level and number of reported readings for a provided postal code. It also provides a list of postal codes with available statistics.''',
    needs_db=True,
    needs_secret=False,
    scenario_instructions='''''',
    functional_tests=[func_test_submit_reading_and_retrieve_statistics, func_test_statistics_for_unknown_postal_code, func_test_list_postal_codes_after_submission, func_test_multiple_readings_same_area_aggregate, func_test_missing_latitude, func_test_non_numeric_decibels, func_test_invalid_postal_code_format, func_test_average_calculation_single_reading, func_test_reading_count_consistency_multiple_codes],
    privacy_tests=[],
)
