# flake8: noqa
# isort: skip_file
import requests

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
    privacy_tests=[],
)
