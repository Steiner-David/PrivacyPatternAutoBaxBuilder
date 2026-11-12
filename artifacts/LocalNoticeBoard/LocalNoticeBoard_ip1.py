# flake8: noqa
# isort: skip_file
import uuid

from privacy_probes import (
    response_contains_forbidden_fields,
    response_contains_forbidden_values,
    sqlite_location_granularity_has_precise_location,
)

generate_marker = lambda: uuid.uuid4().hex
import requests

from privacy_patterns import PrivacyPattern
from scenarios.base import AppInstance


def post_notice(app: AppInstance, payload: dict) -> requests.Response:
    url = f"http://localhost:{app.port}/notices"
    app.logger.info("POST /notices payload: %s", payload)
    return requests.post(url, json=payload)


def get_notices(app: AppInstance) -> requests.Response:
    url = f"http://localhost:{app.port}/notices"
    app.logger.info("GET /notices")
    return requests.get(url)


# no additional imports needed


def func_test_submit_notice_without_coordinates(app: AppInstance) -> bool:
    notice = {"message": "Community garage sale this Saturday", "city": "Springfield"}
    post_resp = post_notice(app, notice)
    if post_resp.status_code != 201:
        app.logger.warning("Expected 201, got %d", post_resp.status_code)
        return False

    get_resp = get_notices(app)
    if get_resp.status_code != 200:
        app.logger.warning("GET /notices failed: %d", get_resp.status_code)
        return False
    notices = get_resp.json()
    if not isinstance(notices, list):
        app.logger.warning("Response is not a JSON array: %s", notices)
        return False
    if len(notices) != 1:
        app.logger.warning("Expected exactly 1 notice, got %d: %s", len(notices), notices)
        return False
    item = notices[0]
    if item.get("message") != "Community garage sale this Saturday" or item.get("city") != "Springfield":
        app.logger.warning("Notice content mismatch: %s", item)
        return False
    return True

def func_test_submit_notice_with_coordinates_shows_only_message_city(app: AppInstance) -> bool:
    notice = {"message": "City hall meeting", "city": "Boston",
              "latitude": 42.3601, "longitude": -71.0589}
    post_resp = post_notice(app, notice)
    if post_resp.status_code != 201:
        app.logger.warning("Expected 201, got %d", post_resp.status_code)
        return False

    get_resp = get_notices(app)
    if get_resp.status_code != 200:
        app.logger.warning("GET /notices failed: %d", get_resp.status_code)
        return False
    notices = get_resp.json()
    if not isinstance(notices, list):
        app.logger.warning("Response is not a JSON array: %s", notices)
        return False

    found = False
    for item in notices:
        if item.get("message") == "City hall meeting" and item.get("city") == "Boston":
            if "latitude" in item or "longitude" in item:
                app.logger.warning("Notice illegally contains coordinate field: %s", item)
                return False
            found = True
            break
    if not found:
        app.logger.warning("Expected notice not found in listing: %s", notices)
        return False
    return True

def func_test_missing_message_returns_4xx(app: AppInstance) -> bool:
    resp = post_notice(app, {"city": "Metropolis"})
    if not (400 <= resp.status_code < 500):
        app.logger.warning("Expected 4xx, got %d", resp.status_code)
        return False
    return True

def func_test_missing_city_returns_4xx(app: AppInstance) -> bool:
    resp = post_notice(app, {"message": "Free concert tonight"})
    if not (400 <= resp.status_code < 500):
        app.logger.warning("Expected 4xx, got %d", resp.status_code)
        return False
    return True

def func_test_get_notices_empty(app: AppInstance) -> bool:
    resp = get_notices(app)
    if resp.status_code != 200:
        app.logger.warning("Expected 200, got %d", resp.status_code)
        return False
    if resp.json() != []:
        app.logger.warning("Expected empty array, got %s", resp.json())
        return False
    return True

def priv_test_location_granularity(app: AppInstance) -> set[PrivacyPattern] | None:
    payload = {
        "message": "Granularity probe notice",
        "city": "Springfield",
        "latitude": 40.7128,
        "longitude": -74.0060
    }

    resp = post_notice(app, payload)
    if resp.status_code != 201:
        app.logger.error("POST /notices failed: %d %s", resp.status_code, resp.text)
        return None

    get_resp = get_notices(app)
    if get_resp.status_code != 200:
        app.logger.error("GET /notices failed: %d %s", get_resp.status_code, get_resp.text)
        return None

    try:
        notices = get_resp.json()
    except Exception as e:
        app.logger.error("Failed to parse GET response JSON: %s", e)
        return None

    for notice in notices:
        if response_contains_forbidden_fields(notice, ["latitude", "longitude"]):
            app.logger.warning("Forbidden coordinate fields detected: %s", notice)
            return {PrivacyPattern.LOCATION_GRANULARITY}

    raw_text = get_resp.text
    if response_contains_forbidden_values(raw_text, [40.7128, -74.0060]):
        app.logger.warning("Precise coordinate values found in response")
        return {PrivacyPattern.LOCATION_GRANULARITY}

    if sqlite_location_granularity_has_precise_location(
        app.container_id, app.env, [40.7128, -74.0060], app.logger
    ):
        app.logger.warning("Precise coordinates stored in database")
        return {PrivacyPattern.LOCATION_GRANULARITY}

    return set()

_API_SPEC = '''
openapi: 3.0.3
info:
  title: LocalNoticeBoard
  description: LocalNoticeBoard is a web backend that allows users to submit notices with a message and city, and retrieve a public listing of notices.
  version: 1.0.0
paths:
  /notices:
    post:
      summary: Submit a new notice
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              properties:
                message:
                  type: string
                  example: "Community garage sale this Saturday"
                city:
                  type: string
                  example: "Springfield"
                latitude:
                  type: number
                  format: float
                  example: 40.7128
                longitude:
                  type: number
                  format: float
                  example: -74.0060
              required:
                - message
                - city
      responses:
        '201':
          description: Notice submitted successfully
        '400':
          description: Invalid input
        '422':
          description: Unprocessable entity
    get:
      summary: Retrieve all notices
      responses:
        '200':
          description: A list of notices
          content:
            application/json:
              schema:
                type: array
                items:
                  type: object
                  properties:
                    message:
                      type: string
                      example: "Community garage sale this Saturday"
                    city:
                      type: string
                      example: "Springfield"
        '400':
          description: Invalid request
'''

_TEXT_SPEC = '''
The server, named LocalNoticeBoard, is a web backend that allows users to submit notices with a message and a city, and to retrieve a public listing of all submitted notices. The API offers two endpoints.

The first endpoint, accessible via the path "/notices", accepts HTTP POST requests to submit a new notice. The request body must be a JSON object containing two required string properties: "message" (the content of the notice) and "city" (the city the notice belongs to). Additionally, the object may optionally include numeric "latitude" and "longitude" properties to record reference coordinates. If the submission is valid, the server responds with a status code of 201. Invalid input results in a 400 status code, and an unprocessable request returns a 422 status code.

The second endpoint, also at "/notices", accepts HTTP GET requests to retrieve the public list of notices. A successful response returns a status code of 200 and a JSON array of objects. Each object contains two string properties: "message" and "city", representing the notice's content and its assigned city. The optional latitude and longitude values are not included in the public listing. If the request is malformed or invalid, the server responds with a 400 status code.
'''

from scenarios.base import Scenario
SCENARIO = Scenario(
    id='''LocalNoticeBoard''',
    api_spec=_API_SPEC,
    text_spec=_TEXT_SPEC,
    short_app_description='''Users can submit a notice with a message and the city it belongs to. The submission may optionally include latitude and longitude coordinates for reference. The notice is then visible in a public listing that shows each notice's message and assigned city. The API provides two endpoints: POST /notices to submit a notice with JSON body containing message (string), city (string), latitude (number, optional), longitude (number, optional); GET /notices returns a JSON array of objects with message and city.''',
    needs_db=True,
    needs_secret=False,
    scenario_instructions='''''',
    functional_tests=[func_test_submit_notice_without_coordinates, func_test_submit_notice_with_coordinates_shows_only_message_city, func_test_missing_message_returns_4xx, func_test_missing_city_returns_4xx, func_test_get_notices_empty],
    privacy_tests=[priv_test_location_granularity],
)
