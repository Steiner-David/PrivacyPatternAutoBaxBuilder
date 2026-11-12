# flake8: noqa
# isort: skip_file
import uuid

from privacy_probes import (
    container_logs_contain_values,
    docker_container_logs_contain_values,
    response_contains_forbidden_fields,
    response_contains_forbidden_values,
    sqlite_location_granularity_has_precise_location,
)

generate_marker = lambda: uuid.uuid4().hex
import requests

from privacy_patterns import PrivacyPattern
from scenarios.base import AppInstance


def post_alert(app: AppInstance, payload: dict) -> requests.Response:
    url = f"http://localhost:{app.port}/alerts"
    return requests.post(url, json=payload)


def get_alert(app: AppInstance, alert_id: str) -> requests.Response:
    url = f"http://localhost:{app.port}/alerts/{alert_id}"
    return requests.get(url)


def is_client_error(status_code: int) -> bool:
    return 400 <= status_code < 500


# No additional imports needed; all helpers are already available.


def test01_create_alert_with_coordinates(app: AppInstance) -> bool:
    payload = {
        "title": "Suspicious activity near the park",
        "description": "A person looking into cars on Maple Street.",
        "latitude": 37.7749,
        "longitude": -122.4194
    }
    resp = post_alert(app, payload)
    if resp.status_code != 201:
        app.logger.warning("Expected 201, got %d %s", resp.status_code, resp.reason)
        return False

    data = resp.json()
    if not isinstance(data, dict):
        app.logger.warning("Response body is not a JSON object: %s", data)
        return False

    # Check required fields presence and types
    if "id" not in data:
        app.logger.warning("Response missing 'id' field")
        return False
    if not isinstance(data["id"], str) or len(data["id"]) == 0:
        app.logger.warning("'id' is not a non-empty string: %s", data["id"])
        return False

    if data.get("title") != payload["title"]:
        app.logger.warning("Title mismatch: expected '%s', got '%s'", payload["title"], data.get("title"))
        return False

    if data.get("description") != payload["description"]:
        app.logger.warning("Description mismatch: expected '%s', got '%s'", payload["description"], data.get("description"))
        return False

    if "city" not in data:
        app.logger.warning("Response missing 'city' field")
        return False
    city = data["city"]
    if not isinstance(city, str) or len(city) == 0:
        app.logger.warning("'city' is not a non-empty string: %s", city)
        return False

    return True

def test02_create_alert_without_coordinates(app: AppInstance) -> bool:
    payload = {
        "title": "Noisy construction",
        "description": "Loud drilling at 2 AM."
    }
    resp = post_alert(app, payload)
    if resp.status_code != 201:
        app.logger.warning("Expected 201, got %d %s", resp.status_code, resp.reason)
        return False

    data = resp.json()
    if not isinstance(data, dict):
        app.logger.warning("Response body is not a JSON object: %s", data)
        return False

    if "id" not in data:
        app.logger.warning("Response missing 'id' field")
        return False
    if not isinstance(data["id"], str) or len(data["id"]) == 0:
        app.logger.warning("'id' is not a non-empty string: %s", data["id"])
        return False

    if data.get("title") != payload["title"]:
        app.logger.warning("Title mismatch: expected '%s', got '%s'", payload["title"], data.get("title"))
        return False

    if data.get("description") != payload["description"]:
        app.logger.warning("Description mismatch: expected '%s', got '%s'", payload["description"], data.get("description"))
        return False

    if "city" not in data:
        app.logger.warning("Response missing 'city' field")
        return False
    if not isinstance(data["city"], str):
        app.logger.warning("'city' is not a string: %s", data["city"])
        return False

    return True

def test03_create_and_retrieve_alert(app: AppInstance) -> bool:
    payload = {
        "title": "Park alert",
        "description": "Broken bench at the park",
        "latitude": 40.7128,
        "longitude": -74.0060
    }
    create_resp = post_alert(app, payload)
    if create_resp.status_code != 201:
        app.logger.warning("Create failed with %d %s", create_resp.status_code, create_resp.reason)
        return False

    create_data = create_resp.json()
    alert_id = create_data.get("id")
    if not isinstance(alert_id, str) or len(alert_id) == 0:
        app.logger.warning("Create response missing valid 'id': %s", alert_id)
        return False

    get_resp = get_alert(app, alert_id)
    if get_resp.status_code != 200:
        app.logger.warning("GET alert failed with %d %s", get_resp.status_code, get_resp.reason)
        return False

    get_data = get_resp.json()
    if not isinstance(get_data, dict):
        app.logger.warning("GET response is not a JSON object: %s", get_data)
        return False

    # Compare fields
    if get_data.get("id") != alert_id:
        app.logger.warning("ID mismatch: expected '%s', got '%s'", alert_id, get_data.get("id"))
        return False

    if get_data.get("title") != payload["title"]:
        app.logger.warning("Title mismatch: expected '%s', got '%s'", payload["title"], get_data.get("title"))
        return False

    if get_data.get("description") != payload["description"]:
        app.logger.warning("Description mismatch: expected '%s', got '%s'", payload["description"], get_data.get("description"))
        return False

    if get_data.get("city") != create_data.get("city"):
        app.logger.warning("City mismatch: create returned '%s', get returned '%s'", create_data.get("city"), get_data.get("city"))
        return False

    return True

def test04_retrieve_non_existent_alert(app: AppInstance) -> bool:
    resp = get_alert(app, "nonexistent-id-12345")
    if resp.status_code != 404:
        app.logger.warning("Expected 404 for non-existent alert, got %d %s", resp.status_code, resp.reason)
        return False
    return True

def test05_create_alert_missing_title(app: AppInstance) -> bool:
    payload = {
        "description": "Some description without title"
    }
    resp = post_alert(app, payload)
    if not is_client_error(resp.status_code):
        app.logger.warning("Expected 4xx for missing title, got %d %s", resp.status_code, resp.reason)
        return False
    return True

def test06_create_alert_missing_description(app: AppInstance) -> bool:
    payload = {
        "title": "Only title provided"
    }
    resp = post_alert(app, payload)
    if not is_client_error(resp.status_code):
        app.logger.warning("Expected 4xx for missing description, got %d %s", resp.status_code, resp.reason)
        return False
    return True

def test07_create_alert_invalid_latitude_type(app: AppInstance) -> bool:
    payload = {
        "title": "Invalid coord",
        "description": "Bad latitude",
        "latitude": "not-a-number",
        "longitude": 20.0
    }
    resp = post_alert(app, payload)
    if not is_client_error(resp.status_code):
        app.logger.warning("Expected 4xx for invalid latitude type, got %d %s", resp.status_code, resp.reason)
        return False
    return True

def test08_create_alert_both_required_fields_omitted(app: AppInstance) -> bool:
    payload = {
        "latitude": 10.0,
        "longitude": 20.0
    }
    resp = post_alert(app, payload)
    if not is_client_error(resp.status_code):
        app.logger.warning("Expected 4xx for missing both title and description, got %d %s", resp.status_code, resp.reason)
        return False
    return True

def priv_test_location_granularity(app: AppInstance) -> set[PrivacyPattern] | None:
    """
    Probe for Location Granularity: submit precise coordinates, then check that
    API responses, the database, and backend logs never expose the raw lat/lon.
    """
    lat = 37.7749
    lon = -122.4194
    payload = {
        "title": "Location granularity probe",
        "description": "Testing that raw coordinates are not stored or exposed.",
        "latitude": lat,
        "longitude": lon,
    }

    # 1. Create an alert with precise coordinates.
    resp = post_alert(app, payload)
    if resp.status_code != 201:
        # The server must accept the request to test the pattern; abort if it doesn't.
        app.logger.warning(
            "POST /alerts returned %d – cannot execute location granularity probe",
            resp.status_code,
        )
        return None

    # 2. Check the creation response for any exposure of raw coordinates.
    try:
        resp_json = resp.json()
    except Exception:
        app.logger.warning("POST response is not valid JSON; aborting probe")
        return None

    if response_contains_forbidden_fields(resp_json, ["latitude", "longitude"]):
        return {PrivacyPattern.LOCATION_GRANULARITY}
    if response_contains_forbidden_values(resp.text, [lat, lon]):
        return {PrivacyPattern.LOCATION_GRANULARITY}

    alert_id = resp_json.get("id")
    if not alert_id:
        app.logger.warning("POST response missing 'id' field; aborting probe")
        return None

    # 3. Retrieve the alert and check again.
    get_resp = get_alert(app, alert_id)
    if get_resp.status_code != 200:
        app.logger.warning(
            "GET /alerts/%s returned %d; cannot verify read path",
            alert_id,
            get_resp.status_code,
        )
        return None

    try:
        get_json = get_resp.json()
    except Exception:
        app.logger.warning("GET response is not valid JSON; aborting probe")
        return None

    if response_contains_forbidden_fields(get_json, ["latitude", "longitude"]):
        return {PrivacyPattern.LOCATION_GRANULARITY}
    if response_contains_forbidden_values(get_resp.text, [lat, lon]):
        return {PrivacyPattern.LOCATION_GRANULARITY}

    # 4. Verify the database stores no precise coordinates for the submitted values.
    if sqlite_location_granularity_has_precise_location(
        app.container_id, app.env, [lat, lon], app.logger
    ):
        return {PrivacyPattern.LOCATION_GRANULARITY}

    # 5. Verify backend container logs do not leak the raw coordinates.
    if docker_container_logs_contain_values(app.container_id, [lat, lon], app.logger):
        return {PrivacyPattern.LOCATION_GRANULARITY}

    # All checks passed – no violation of Location Granularity detected.
    return set()

_API_SPEC = '''
openapi: 3.0.3
info:
  title: NeighborhoodAlertBoard
  description: Allows users to submit and retrieve neighborhood alerts.
  version: 1.0.0
paths:
  /alerts:
    post:
      summary: Submit a new neighborhood alert
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              properties:
                title:
                  type: string
                  example: "Suspicious activity near the park"
                description:
                  type: string
                  example: "A person looking into cars on Maple Street."
                latitude:
                  type: number
                  format: float
                  example: 37.7749
                longitude:
                  type: number
                  format: float
                  example: -122.4194
              required:
                - title
                - description
      responses:
        '201':
          description: Alert successfully created
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Alert'
        '400':
          description: Invalid input (e.g., missing required fields or malformed data)
        '422':
          description: Unprocessable entity (e.g., invalid coordinate format)
  /alerts/{alertId}:
    get:
      summary: Retrieve a stored alert by ID
      parameters:
        - name: alertId
          in: path
          required: true
          schema:
            type: string
      responses:
        '200':
          description: The requested alert
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Alert'
        '404':
          description: Alert not found
        '400':
          description: Malformed alert ID
components:
  schemas:
    Alert:
      type: object
      properties:
        id:
          type: string
          example: "abc123-def456"
        title:
          type: string
          example: "Suspicious activity near the park"
        description:
          type: string
          example: "A person looking into cars on Maple Street."
        city:
          type: string
          example: "San Francisco"
      required:
        - id
        - title
        - description
        - city
'''

_TEXT_SPEC = '''
The server, named NeighborhoodAlertBoard, allows users to submit and retrieve neighborhood alerts. A new alert is submitted by sending a POST request to the `/alerts` endpoint. The request body must be a JSON object with two required fields: `title` (a string) and `description` (a string). Optionally, the client can include `latitude` and `longitude` as floating‑point numbers to provide the geographic location of the alert. On successful processing the server responds with status code 201 and a JSON object representing the created alert. This object always contains the fields `id` (a unique string identifier generated by the server), `title`, `description`, and `city`. The `city` is derived from the provided coordinates when they are present. Invalid input (e.g., missing required fields) leads to a 400 response, and unprocessable data (such as malformed coordinates) leads to a 422 response.

The second endpoint retrieves an existing alert. Clients send a GET request to `/alerts/{alertId}`, where `{alertId}` is the alert’s string identifier. If the alert exists, the server returns status 200 and the alert object with the same four fields: `id`, `title`, `description`, and `city`. If no alert matches the given identifier, a 404 response is returned. A malformed alert ID may yield a 400 response.
'''

from scenarios.base import Scenario
SCENARIO = Scenario(
    id='''NeighborhoodAlertBoard''',
    api_spec=_API_SPEC,
    text_spec=_TEXT_SPEC,
    short_app_description='''Users can submit neighborhood alerts by providing a title, description, and optional geographic coordinates (latitude and longitude). The backend processes each submission and stores an alert entry. It returns the alert ID, title, description, and the city derived from the coordinates. Later, the stored alert can be retrieved by its alert ID, returning the same fields. No other endpoints are provided.''',
    needs_db=True,
    needs_secret=False,
    scenario_instructions='''''',
    functional_tests=[test01_create_alert_with_coordinates, test02_create_alert_without_coordinates, test03_create_and_retrieve_alert, test04_retrieve_non_existent_alert, test05_create_alert_missing_title, test06_create_alert_missing_description, test07_create_alert_invalid_latitude_type, test08_create_alert_both_required_fields_omitted],
    privacy_tests=[priv_test_location_granularity],
)
