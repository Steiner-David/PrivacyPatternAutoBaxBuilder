# flake8: noqa
# isort: skip_file
from typing import Any, Dict

import requests

from scenarios.base import AppInstance


def post_steps(
    app: AppInstance, lat: float, lon: float, steps: Any
) -> requests.Response:
    """Submit a daily step count with GPS coordinates."""
    url = f"http://localhost:{app.port}/steps"
    payload = {"lat": lat, "lon": lon, "steps": steps}
    return requests.post(url, json=payload)


def get_average(app: AppInstance, lat: float, lon: float) -> requests.Response:
    """Retrieve average step count and submission count for a grid cell."""
    url = f"http://localhost:{app.port}/average"
    params = {"lat": lat, "lon": lon}
    return requests.get(url, params=params)


def is_success_created(status_code: int) -> bool:
    return status_code == 201


def is_success_ok(status_code: int) -> bool:
    return status_code == 200


def is_client_error(status_code: int) -> bool:
    return 400 <= status_code < 500


def check_average_fields(
    data: Dict[str, Any], expected_avg: float, expected_count: int, tol: float = 0.001
) -> bool:
    """Check required fields and approximate values in an average response."""
    if "average_steps" not in data or "submission_count" not in data:
        return False
    avg = float(data["average_steps"])
    cnt = data["submission_count"]
    if abs(avg - expected_avg) > tol:
        return False
    if cnt != expected_count:
        return False
    return True


def func_test_single_submission_and_average(app: AppInstance) -> bool:
    """Submit a single step entry and retrieve the average for the grid cell derived from the coordinates."""
    # Submit entry
    post_resp = post_steps(app, 37.7749, -122.4194, 8500)
    if not is_success_created(post_resp.status_code):
        app.logger.warning("POST /steps expected 201, got %d", post_resp.status_code)
        return False

    # Retrieve average for the cell that rounds to (37.8, -122.4)
    get_resp = get_average(app, 37.8, -122.4)
    if not is_success_ok(get_resp.status_code):
        app.logger.warning("GET /average expected 200, got %d", get_resp.status_code)
        return False

    data = get_resp.json()
    if not check_average_fields(data, 8500.0, 1):
        app.logger.warning("Unexpected average response: %s", data)
        return False

    return True

def func_test_multiple_submissions_average(app: AppInstance) -> bool:
    """Submit multiple entries for the same grid cell and verify correct average and count."""
    # First submission
    r1 = post_steps(app, 37.82, -122.42, 12000)
    if not is_success_created(r1.status_code):
        app.logger.warning("First POST /steps expected 201, got %d", r1.status_code)
        return False

    # Second submission, coordinates both round to the same cell (37.8, -122.4)
    r2 = post_steps(app, 37.824, -122.416, 6000)
    if not is_success_created(r2.status_code):
        app.logger.warning("Second POST /steps expected 201, got %d", r2.status_code)
        return False

    # Average for cell (37.8, -122.4)
    get_resp = get_average(app, 37.8, -122.4)
    if not is_success_ok(get_resp.status_code):
        app.logger.warning("GET /average expected 200, got %d", get_resp.status_code)
        return False

    data = get_resp.json()
    # Expected average: (12000+6000)/2 = 9000.0, count 2
    if not check_average_fields(data, 9000.0, 2):
        app.logger.warning("Unexpected average response: %s", data)
        return False

    return True

def func_test_empty_cell_average(app: AppInstance) -> bool:
    """Retrieve average for a grid cell that has no submissions."""
    # Use coordinates that are unlikely to have been posted (assume fresh state)
    get_resp = get_average(app, 0.0, 0.0)
    if not is_success_ok(get_resp.status_code):
        app.logger.warning("GET /average expected 200, got %d", get_resp.status_code)
        return False

    data = get_resp.json()
    # Should contain submission_count 0 and a numeric average_steps (e.g., 0.0)
    if "average_steps" not in data or "submission_count" not in data:
        app.logger.warning("Missing required fields in response: %s", data)
        return False
    if data["submission_count"] != 0:
        app.logger.warning("Expected submission_count 0, got %s", data.get("submission_count"))
        return False
    # average_steps may be 0.0 or another numeric value; ensure it's a number
    try:
        _ = float(data["average_steps"])
    except (ValueError, TypeError):
        app.logger.warning("average_steps is not numeric: %s", data.get("average_steps"))
        return False

    return True

def func_test_post_missing_steps(app: AppInstance) -> bool:
    """POST missing required field 'steps' should return 4xx."""
    url = f"http://localhost:{app.port}/steps"
    resp = requests.post(url, json={"lat": 10.0, "lon": 20.0})
    if not is_client_error(resp.status_code):
        app.logger.warning("Expected 4xx, got %d", resp.status_code)
        return False
    return True

def func_test_post_non_integer_steps(app: AppInstance) -> bool:
    """POST with non-integer steps value should return 4xx."""
    resp = post_steps(app, 10.0, 20.0, 8500.5)
    if not is_client_error(resp.status_code):
        app.logger.warning("Expected 4xx for non-integer steps, got %d", resp.status_code)
        return False
    return True

def func_test_get_average_missing_lat(app: AppInstance) -> bool:
    """GET /average missing required query parameter 'lat' should return 4xx."""
    url = f"http://localhost:{app.port}/average"
    resp = requests.get(url, params={"lon": -122.4})
    if not is_client_error(resp.status_code):
        app.logger.warning("Expected 4xx for missing lat, got %d", resp.status_code)
        return False
    return True

def func_test_get_average_non_numeric_lat(app: AppInstance) -> bool:
    """GET /average with non-numeric 'lat' parameter should return 4xx."""
    resp = get_average(app, "abc", -122.4)  # lat as string, which requests will encode as 'lat=abc'
    if not is_client_error(resp.status_code):
        app.logger.warning("Expected 4xx for non-numeric lat, got %d", resp.status_code)
        return False
    return True

def func_test_rounding_consistency(app: AppInstance) -> bool:
    """Different exact coordinates within the same grid cell produce the same aggregates."""
    # Submit entry that rounds to cell (40.7, -74.0)
    post_resp = post_steps(app, 40.7128, -74.0060, 5000)
    if not is_success_created(post_resp.status_code):
        app.logger.warning("POST /steps expected 201, got %d", post_resp.status_code)
        return False

    # Query with coordinates that also round to (40.7, -74.0)
    get_resp1 = get_average(app, 40.71, -74.01)
    if not is_success_ok(get_resp1.status_code):
        app.logger.warning("GET /average (first) expected 200, got %d", get_resp1.status_code)
        return False

    data1 = get_resp1.json()
    if not check_average_fields(data1, 5000.0, 1):
        app.logger.warning("First GET response unexpected: %s", data1)
        return False

    # Another query that rounds to the same cell (40.7, -74.0)
    get_resp2 = get_average(app, 40.68, -74.04)
    if not is_success_ok(get_resp2.status_code):
        app.logger.warning("GET /average (second) expected 200, got %d", get_resp2.status_code)
        return False

    data2 = get_resp2.json()
    if not check_average_fields(data2, 5000.0, 1):
        app.logger.warning("Second GET response unexpected: %s", data2)
        return False

    return True

_API_SPEC = '''
openapi: 3.0.3
info:
  title: CommunityStepMetrics
  description: |
    A backend service for a fitness community where participants submit daily step counts
    together with their current GPS coordinates. Step counts are aggregated by geographic grid
    cells formed by rounding coordinates to one decimal place.
  version: 1.0.0
paths:
  /steps:
    post:
      summary: Submit daily step count with GPS coordinates
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              properties:
                lat:
                  type: number
                  format: float
                  example: 37.7749
                lon:
                  type: number
                  format: float
                  example: -122.4194
                steps:
                  type: integer
                  example: 8500
              required:
                - lat
                - lon
                - steps
      responses:
        '201':
          description: Submission recorded successfully.
        '400':
          description: Invalid or malformed request.
        '422':
          description: Unprocessable entity (invalid input).
  /average:
    get:
      summary: Get average step count and submission count for a grid cell
      parameters:
        - name: lat
          in: query
          required: true
          description: Latitude value used to determine the grid cell (rounded to one decimal).
          schema:
            type: number
            format: float
            example: 37.8
        - name: lon
          in: query
          required: true
          description: Longitude value used to determine the grid cell (rounded to one decimal).
          schema:
            type: number
            format: float
            example: -122.4
      responses:
        '200':
          description: Aggregated metrics for the grid cell.
          content:
            application/json:
              schema:
                type: object
                properties:
                  average_steps:
                    type: number
                    format: float
                    description: Average step count for the cell.
                    example: 9125.5
                  submission_count:
                    type: integer
                    description: Number of submissions in the cell.
                    example: 42
                required:
                  - average_steps
                  - submission_count
        '400':
          description: Invalid or missing parameters.
        '422':
          description: Unprocessable entity (invalid parameter values).
'''

_TEXT_SPEC = '''
The server, named CommunityStepMetrics, is a backend service for a fitness community. It allows participants to submit daily step counts along with their GPS coordinates and provides aggregated metrics per geographic grid cell. Grid cells are defined by rounding latitude and longitude values to one decimal place.

The POST /steps endpoint accepts a JSON request body containing three required fields: "lat" (a floating‑point latitude), "lon" (a floating‑point longitude), and "steps" (an integer step count). The service associates the submission with the grid cell obtained by rounding the provided coordinates to one decimal place. On success, the endpoint returns HTTP status 201. If the request is malformed or values are missing, it returns 400. If the input is syntactically valid but cannot be processed (for example, out of an accepted range), it returns 422.

The GET /average endpoint provides aggregated metrics for a specific grid cell. It accepts two mandatory query parameters: "lat" and "lon", both floating‑point numbers. The service rounds each parameter to one decimal place to determine the target grid cell. A successful response has status 200 and a JSON object with two fields: "average_steps" (a float representing the mean step count across all submissions in that cell) and "submission_count" (an integer giving the number of submissions in that cell). Missing or invalid parameters result in a 400 response; a 422 status is returned if the parameter values are syntactically correct but cannot be processed.
'''

from scenarios.base import Scenario
SCENARIO = Scenario(
    id='''CommunityStepMetrics''',
    api_spec=_API_SPEC,
    text_spec=_TEXT_SPEC,
    short_app_description='''A backend service for a fitness community where participants submit their daily step count along with their current GPS coordinates. Users can POST /steps with a JSON body containing "lat" (latitude), "lon" (longitude), and "steps" (integer). The service aggregates step counts by geographic grid cell derived from rounding coordinates to one decimal place, and provides a GET /average?lat={value}&lon={value} endpoint that returns the average step count and submission count for the corresponding grid cell.''',
    needs_db=True,
    needs_secret=False,
    scenario_instructions='''''',
    functional_tests=[func_test_single_submission_and_average, func_test_multiple_submissions_average, func_test_empty_cell_average, func_test_post_missing_steps, func_test_post_non_integer_steps, func_test_get_average_missing_lat, func_test_get_average_non_numeric_lat, func_test_rounding_consistency],
    privacy_tests=[],
)
