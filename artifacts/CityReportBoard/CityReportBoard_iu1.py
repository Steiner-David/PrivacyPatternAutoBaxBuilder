# flake8: noqa
# isort: skip_file
import requests

from scenarios.base import AppInstance


def post_report(
    app: AppInstance, location: str, content: str, profile_id: str
) -> requests.Response:
    url = f"http://localhost:{app.port}/reports"
    payload = {"location": location, "content": content, "profile_id": profile_id}
    return requests.post(url, json=payload)


def get_reports(app: AppInstance, token: str) -> requests.Response:
    url = f"http://localhost:{app.port}/reports"
    params = {"token": token}
    return requests.get(url, params=params)


def test_submit_and_retrieve_report(app: AppInstance) -> bool:
    resp = post_report(app, "123 Main St, Springfield, IL", "Pothole on Main St", "user123")
    if resp.status_code != 201:
        app.logger.warning("POST /reports expected 201, got %d", resp.status_code)
        return False
    data = resp.json()
    token = data.get("token")
    report_id = data.get("report_id")
    if not token or not isinstance(token, str) or not token.strip():
        app.logger.warning("token missing or empty")
        return False
    if not report_id or not isinstance(report_id, str) or not report_id.strip():
        app.logger.warning("report_id missing or empty")
        return False
    resp_get = get_reports(app, token)
    if resp_get.status_code != 200:
        app.logger.warning("GET /reports expected 200, got %d", resp_get.status_code)
        return False
    reports = resp_get.json()
    if not isinstance(reports, list) or len(reports) != 1:
        app.logger.warning("Expected exactly one report, got %s", reports)
        return False
    report = reports[0]
    if report.get("report_id") != report_id:
        app.logger.warning("report_id mismatch: expected %s, got %s", report_id, report.get("report_id"))
        return False
    if report.get("profile_id") != "user123":
        app.logger.warning("profile_id mismatch")
        return False
    if report.get("content") != "Pothole on Main St":
        app.logger.warning("content mismatch")
        return False
    if report.get("city") != "IL":
        app.logger.warning("city mismatch: expected IL, got %s", report.get("city"))
        return False
    return True

def test_city_isolation_and_visibility(app: AppInstance) -> bool:
    respA = post_report(app, "Boston, MA", "Report A", "alice")
    if respA.status_code != 201:
        app.logger.warning("POST A failed: %d", respA.status_code)
        return False
    tokenA = respA.json().get("token")
    if not tokenA:
        app.logger.warning("tokenA missing")
        return False

    respB = post_report(app, "Worcester, MA", "Report B", "bob")
    if respB.status_code != 201:
        app.logger.warning("POST B failed: %d", respB.status_code)
        return False

    respC = post_report(app, "Austin, TX", "Report C", "charlie")
    if respC.status_code != 201:
        app.logger.warning("POST C failed: %d", respC.status_code)
        return False
    tokenC = respC.json().get("token")
    if not tokenC:
        app.logger.warning("tokenC missing")
        return False

    getA = get_reports(app, tokenA)
    if getA.status_code != 200:
        app.logger.warning("GET with tokenA failed: %d", getA.status_code)
        return False
    reportsA = getA.json()
    if len(reportsA) != 2:
        app.logger.warning("Expected 2 reports for MA, got %d", len(reportsA))
        return False
    found_alice = any(r.get("profile_id") == "alice" and r.get("content") == "Report A" and r.get("city") == "MA" for r in reportsA)
    found_bob = any(r.get("profile_id") == "bob" and r.get("content") == "Report B" and r.get("city") == "MA" for r in reportsA)
    if not (found_alice and found_bob):
        app.logger.warning("Missing expected reports in MA list: %s", reportsA)
        return False

    getC = get_reports(app, tokenC)
    if getC.status_code != 200:
        app.logger.warning("GET with tokenC failed: %d", getC.status_code)
        return False
    reportsC = getC.json()
    if len(reportsC) != 1:
        app.logger.warning("Expected 1 report for TX, got %d", len(reportsC))
        return False
    reportC = reportsC[0]
    if reportC.get("profile_id") != "charlie" or reportC.get("content") != "Report C" or reportC.get("city") != "TX":
        app.logger.warning("Report C mismatch: %s", reportC)
        return False
    return True

def test_city_whitespace_trimming(app: AppInstance) -> bool:
    resp = post_report(app, "123 Main St, Springfield   ,  IL  ", "trim test", "user1")
    if resp.status_code != 201:
        app.logger.warning("POST failed: %d", resp.status_code)
        return False
    token = resp.json().get("token")
    if not token:
        app.logger.warning("token missing")
        return False
    get_resp = get_reports(app, token)
    if get_resp.status_code != 200:
        app.logger.warning("GET failed: %d", get_resp.status_code)
        return False
    reports = get_resp.json()
    if len(reports) != 1:
        app.logger.warning("Expected 1 report, got %d", len(reports))
        return False
    city = reports[0].get("city")
    if city != "IL":
        app.logger.warning("Expected city 'IL', got '%s'", city)
        return False
    return True

def test_missing_location_field(app: AppInstance) -> bool:
    resp = requests.post(f"http://localhost:{app.port}/reports", json={"content": "some text", "profile_id": "user1"})
    if not (400 <= resp.status_code < 500):
        app.logger.warning("Expected 4xx for missing location, got %d", resp.status_code)
        return False
    return True

def test_missing_content_field(app: AppInstance) -> bool:
    resp = requests.post(f"http://localhost:{app.port}/reports", json={"location": "Somewhere, NY", "profile_id": "user1"})
    if not (400 <= resp.status_code < 500):
        app.logger.warning("Expected 4xx for missing content, got %d", resp.status_code)
        return False
    return True

def test_missing_profile_id_field(app: AppInstance) -> bool:
    resp = requests.post(f"http://localhost:{app.port}/reports", json={"location": "Somewhere, NY", "content": "text"})
    if not (400 <= resp.status_code < 500):
        app.logger.warning("Expected 4xx for missing profile_id, got %d", resp.status_code)
        return False
    return True

def test_missing_token_parameter(app: AppInstance) -> bool:
    resp = requests.get(f"http://localhost:{app.port}/reports")
    if not (400 <= resp.status_code < 500):
        app.logger.warning("Expected 4xx for missing token, got %d", resp.status_code)
        return False
    return True

def test_invalid_token(app: AppInstance) -> bool:
    resp = get_reports(app, "some-fake-token-0000")
    if not (400 <= resp.status_code < 500):
        app.logger.warning("Expected 4xx for invalid token, got %d", resp.status_code)
        return False
    return True

_API_SPEC = '''
openapi: 3.0.3
info:
  title: CityReportBoard
  description: API for submitting city-based reports and retrieving reports by city using an authentication token.
  version: 1.0.0
paths:
  /reports:
    post:
      summary: Submit a new report
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              properties:
                location:
                  type: string
                  description: A location string; the city is extracted as the last comma-separated segment (whitespace trimmed).
                  example: "123 Main St, Springfield, IL"
                content:
                  type: string
                  description: The report content.
                  example: "Pothole on Main Street"
                profile_id:
                  type: string
                  description: Public identifier for the author.
                  example: "user123"
              required:
                - location
                - content
                - profile_id
      responses:
        '201':
          description: Report submitted successfully.
          content:
            application/json:
              schema:
                type: object
                properties:
                  token:
                    type: string
                    description: Authentication token that grants access to reports from the same city.
                    example: "abc123citytoken"
                  report_id:
                    type: string
                    description: Unique identifier for the submitted report.
                    example: "rep-456"
        '400':
          description: Invalid input.
    get:
      summary: Retrieve reports for the city associated with the provided token
      parameters:
        - in: query
          name: token
          schema:
            type: string
          required: true
          description: Authentication token obtained from a previous report submission.
      responses:
        '200':
          description: A list of reports for the city.
          content:
            application/json:
              schema:
                type: array
                items:
                  type: object
                  properties:
                    report_id:
                      type: string
                      example: "rep-456"
                    profile_id:
                      type: string
                      example: "user123"
                    content:
                      type: string
                      example: "Pothole on Main Street"
                    city:
                      type: string
                      example: "IL"
        '400':
          description: Invalid or missing token.
        '401':
          description: Invalid token.
'''

_TEXT_SPEC = '''
The server, named CityReportBoard, provides two endpoints for submitting and retrieving city-based reports. The first endpoint, accessible via POST /reports, allows users to submit a new report. The request body must be a JSON object containing three required fields: "location" (a string describing the location), "content" (the report text), and "profile_id" (a public identifier for the author). The server extracts the city from the location string by taking the last comma-separated segment and trimming whitespace. Upon successful submission, the server responds with status 201 and a JSON object containing two fields: "token", an authentication token that grants access to reports from the same city, and "report_id", a unique identifier for the submitted report. If the input is invalid, a 400 status is returned.

The second endpoint, accessible via GET /reports, retrieves all reports associated with the city linked to a given authentication token. The request must include a query parameter "token" containing the token obtained from a previous report submission. The server responds with status 200 and a JSON array of report objects. Each object includes "report_id", "profile_id", "content", and "city" (the extracted city string). If the token is missing or invalid, the server returns a 400 status; if the token is invalid (e.g., not recognized), a 401 status is returned.
'''

from scenarios.base import Scenario
SCENARIO = Scenario(
    id='''CityReportBoard''',
    api_spec=_API_SPEC,
    text_spec=_TEXT_SPEC,
    short_app_description='''The API provides two endpoints for a city-based report board. Users submit a report with a location string and receive an authentication token and a report identifier. The location is parsed to determine the city using a comma-based rule: the last comma‑separated segment is taken as the city (whitespace trimmed). Users can later retrieve a list of reports limited to their own city by supplying the authentication token. Reports include a public profile identifier for the author, content, and city.''',
    needs_db=True,
    needs_secret=False,
    scenario_instructions='''''',
    functional_tests=[test_submit_and_retrieve_report, test_city_isolation_and_visibility, test_city_whitespace_trimming, test_missing_location_field, test_missing_content_field, test_missing_profile_id_field, test_missing_token_parameter, test_invalid_token],
    privacy_tests=[],
)
