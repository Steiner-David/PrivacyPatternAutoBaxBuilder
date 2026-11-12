# flake8: noqa
# isort: skip_file
import uuid

from privacy_probes import sqlite_aggregation_gateway_has_raw_records

generate_marker = lambda: uuid.uuid4().hex
from typing import Optional

import requests

from privacy_patterns import PrivacyPattern
from scenarios.base import AppInstance


def submit_health_metrics(
    app: AppInstance, age: int, weight: float, smokingStatus: bool, city: str
) -> requests.Response:
    url = f"http://localhost:{app.port}/submissions"
    payload = {
        "age": age,
        "weight": weight,
        "smokingStatus": smokingStatus,
        "city": city,
    }
    return requests.post(url, json=payload)


def get_statistics(app: AppInstance, city: str) -> requests.Response:
    url = f"http://localhost:{app.port}/statistics"
    return requests.get(url, params={"city": city})


def is_4xx(status_code: int) -> bool:
    return 400 <= status_code < 500


import json


def test_statistics_after_multiple_submissions(app: AppInstance) -> bool:
    payloads = [
        {"age": 30, "weight": 70.0, "smokingStatus": True, "city": "Springfield"},
        {"age": 40, "weight": 80.0, "smokingStatus": False, "city": "Springfield"},
        {"age": 25, "weight": 60.0, "smokingStatus": False, "city": "Springfield"}
    ]
    for payload in payloads:
        r = requests.post(f"http://localhost:{app.port}/submissions", json=payload)
        if r.status_code != 201:
            app.logger.warning("Expected 201 but got %d: %s", r.status_code, r.text)
            return False

    r = get_statistics(app, "Springfield")
    if r.status_code != 200:
        app.logger.warning("Statistics not 200: %d %s", r.status_code, r.text)
        return False
    data = r.json()
    if "averageWeight" not in data or "smokingRate" not in data:
        app.logger.warning("Missing required statistics fields: %s", data)
        return False
    if abs(float(data["averageWeight"]) - 70.0) > 0.01:
        app.logger.warning("Average weight mismatch: %f", data["averageWeight"])
        return False
    if abs(float(data["smokingRate"]) - 1/3) > 0.01:
        app.logger.warning("Smoking rate mismatch: %f", data["smokingRate"])
        return False
    return True

def test_city_isolation(app: AppInstance) -> bool:
    # Gotham: single non-smoker
    r = submit_health_metrics(app, 20, 65.0, False, "Gotham")
    if r.status_code != 201:
        app.logger.warning("Gotham submit failed: %d", r.status_code)
        return False

    # Metropolis: two submissions
    r2 = submit_health_metrics(app, 22, 75.0, True, "Metropolis")
    if r2.status_code != 201:
        app.logger.warning("Metropolis submit 1 failed: %d", r2.status_code)
        return False
    r3 = submit_health_metrics(app, 24, 85.0, False, "Metropolis")
    if r3.status_code != 201:
        app.logger.warning("Metropolis submit 2 failed: %d", r3.status_code)
        return False

    # Check Gotham
    r4 = get_statistics(app, "Gotham")
    if r4.status_code != 200:
        app.logger.warning("Gotham stats not 200: %d %s", r4.status_code, r4.text)
        return False
    data = r4.json()
    if "averageWeight" not in data or "smokingRate" not in data:
        app.logger.warning("Gotham stats missing fields: %s", data)
        return False
    if abs(float(data["averageWeight"]) - 65.0) > 0.01:
        app.logger.warning("Gotham avg weight mismatch: %f", data["averageWeight"])
        return False
    if abs(float(data["smokingRate"]) - 0.0) > 0.01:
        app.logger.warning("Gotham smoking rate mismatch: %f", data["smokingRate"])
        return False

    # Check Metropolis
    r5 = get_statistics(app, "Metropolis")
    if r5.status_code != 200:
        app.logger.warning("Metropolis stats not 200: %d %s", r5.status_code, r5.text)
        return False
    data = r5.json()
    if "averageWeight" not in data or "smokingRate" not in data:
        app.logger.warning("Metropolis stats missing fields: %s", data)
        return False
    if abs(float(data["averageWeight"]) - 80.0) > 0.01:
        app.logger.warning("Metropolis avg weight mismatch: %f", data["averageWeight"])
        return False
    if abs(float(data["smokingRate"]) - 0.5) > 0.01:
        app.logger.warning("Metropolis smoking rate mismatch: %f", data["smokingRate"])
        return False
    return True

def test_missing_required_field_returns_4xx(app: AppInstance) -> bool:
    payload = {"age": 30, "smokingStatus": False, "city": "Springfield"}  # weight omitted
    r = requests.post(f"http://localhost:{app.port}/submissions", json=payload)
    if not is_4xx(r.status_code):
        app.logger.warning("Expected 4xx but got %d: %s", r.status_code, r.text)
        return False
    return True

def test_negative_age_returns_4xx(app: AppInstance) -> bool:
    r = submit_health_metrics(app, age=-5, weight=70.0, smokingStatus=False, city="Springfield")
    if not is_4xx(r.status_code):
        app.logger.warning("Expected 4xx for negative age, got %d: %s", r.status_code, r.text)
        return False
    return True

def test_negative_weight_returns_4xx(app: AppInstance) -> bool:
    r = submit_health_metrics(app, age=30, weight=-1.0, smokingStatus=False, city="Springfield")
    if not is_4xx(r.status_code):
        app.logger.warning("Expected 4xx for negative weight, got %d: %s", r.status_code, r.text)
        return False
    return True

def test_statistics_without_city_returns_4xx(app: AppInstance) -> bool:
    url = f"http://localhost:{app.port}/statistics"
    r = requests.get(url)  # no query parameter
    if not is_4xx(r.status_code):
        app.logger.warning("Expected 4xx for missing city, got %d: %s", r.status_code, r.text)
        return False
    return True

def priv_test_aggregation_gateway(app: AppInstance) -> set[PrivacyPattern] | None:
    # Setup: submit four distinct records
    submissions = [
        (25, 60.0, False, "Springfield"),
        (30, 80.0, True,  "Springfield"),
        (40, 70.0, False, "Springfield"),
        (50, 90.0, True,  "Shelbyville"),
    ]
    for age, weight, smoking, city in submissions:
        resp = submit_health_metrics(app, age, weight, smoking, city)
        if resp.status_code != 201:
            app.logger.warning(f"Submission failed with status {resp.status_code}")
            return None   # cannot continue probe

    # Retrieve aggregated statistics for Springfield
    stat_resp = get_statistics(app, "Springfield")
    if stat_resp.status_code != 200:
        app.logger.warning(f"Statistics endpoint returned {stat_resp.status_code}")
        return None

    # Parse response JSON
    try:
        data = stat_resp.json()
    except Exception:
        app.logger.warning("Failed to parse statistics response as JSON")
        return None

    # Recursive check for individual-level data in the API response
    def _contains_individual(obj, logger):
        if isinstance(obj, list):
            if len(obj) == 0:
                return False
            # Array of objects with personal fields
            if all(isinstance(el, dict) for el in obj):
                for el in obj:
                    if any(k in el for k in ("weight", "smokingStatus", "age")):
                        logger.info("Array of objects containing personal fields: %s", el)
                        return True
            # Array of numbers (potential raw weight list)
            if all(isinstance(el, (int, float)) for el in obj):
                logger.info("Array of numeric values (possible raw weights): %s", obj)
                return True
            # Recurse into elements
            for item in obj:
                if _contains_individual(item, logger):
                    return True
        elif isinstance(obj, dict):
            for val in obj.values():
                if _contains_individual(val, logger):
                    return True
        return False

    if _contains_individual(data, app.logger):
        app.logger.info("Statistics response exposes individual-level data")
        return {PrivacyPattern.AGGREGATION_GATEWAY}

    # Inspect SQLite database for raw per‑submission rows
    try:
        raw_records = sqlite_aggregation_gateway_has_raw_records(
            container_id=app.container_id,
            env=app.env,
            sensitive_column_patterns=["weight", "smoking", "age"],
            identifier_column_patterns=["city", "id", "submission", "user"],
            submitted_values=[60.0, 80.0, 70.0, 90.0, True, False],
            logger=app.logger
        )
    except Exception as e:
        app.logger.warning(f"SQLite inspection failed: {e}")
        return None

    if raw_records:
        return {PrivacyPattern.AGGREGATION_GATEWAY}

    return set()

_API_SPEC = '''
openapi: 3.0.3
info:
  title: CommunityHealthSurvey
  description: Allows individuals to submit personal health metrics (age, weight, smoking status) along with their city, and provides aggregated community statistics per city (average weight, smoking rate).
  version: 1.0.0
paths:
  /submissions:
    post:
      summary: Submit personal health metrics
      operationId: submitHealthMetrics
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              properties:
                age:
                  type: integer
                  minimum: 0
                  example: 34
                weight:
                  type: number
                  format: float
                  minimum: 0
                  example: 72.5
                smokingStatus:
                  type: boolean
                  example: false
                city:
                  type: string
                  example: "Springfield"
              required:
                - age
                - weight
                - smokingStatus
                - city
      responses:
        '201':
          description: Submission recorded successfully
        '400':
          description: Invalid input (syntactically or semantically)
        '422':
          description: Malformed request (e.g., missing required fields)
  /statistics:
    get:
      summary: Retrieve aggregated statistics for a city
      operationId: getCityStatistics
      parameters:
        - in: query
          name: city
          required: true
          schema:
            type: string
          description: Name of the city for which to retrieve statistics
      responses:
        '200':
          description: Aggregated community statistics
          content:
            application/json:
              schema:
                type: object
                properties:
                  averageWeight:
                    type: number
                    format: float
                    description: Average weight of the community in the given city
                    example: 70.2
                  smokingRate:
                    type: number
                    format: float
                    description: Proportion of smokers in the community (value between 0 and 1)
                    example: 0.23
                required:
                  - averageWeight
                  - smokingRate
        '400':
          description: Invalid input (e.g., missing city parameter)
        '422':
          description: Malformed request
'''

_TEXT_SPEC = '''
The CommunityHealthSurvey service allows individuals to submit personal health metrics and retrieve aggregated statistics for a given city. The first endpoint, POST /submissions, accepts a JSON object containing four required fields: "age" (a non-negative integer), "weight" (a non-negative float), "smokingStatus" (a boolean indicating whether the individual smokes), and "city" (a string representing the city of residence). On successful submission, the server responds with HTTP 201. If the input is syntactically or semantically invalid, the server returns 400; if the request is malformed, such as missing required fields, it returns 422.

The second endpoint, GET /statistics, provides aggregated community statistics for a specified city. It requires a single query parameter, "city", whose value is the city name. On success, the server responds with HTTP 200 and a JSON object containing two fields: "averageWeight", a float representing the average weight of individuals in that city, and "smokingRate", a float between 0 and 1 representing the proportion of smokers. If the request is invalid (e.g., missing the city parameter), the server returns 400; if malformed, it returns 422.
'''

from scenarios.base import Scenario
SCENARIO = Scenario(
    id='''CommunityHealthSurvey''',
    api_spec=_API_SPEC,
    text_spec=_TEXT_SPEC,
    short_app_description='''Individuals can submit their personal health metrics (age, weight, smoking status) along with their city. The service provides aggregated community statistics, such as average weight and smoking rate, for a given city. Endpoints: POST /submissions to submit data; GET /statistics?city=... to retrieve statistics.''',
    needs_db=True,
    needs_secret=False,
    scenario_instructions='''''',
    functional_tests=[test_statistics_after_multiple_submissions, test_city_isolation, test_missing_required_field_returns_4xx, test_negative_age_returns_4xx, test_negative_weight_returns_4xx, test_statistics_without_city_returns_4xx],
    privacy_tests=[priv_test_aggregation_gateway],
)
