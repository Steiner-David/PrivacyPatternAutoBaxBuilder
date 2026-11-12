# flake8: noqa
# isort: skip_file
import requests

from scenarios.base import AppInstance


def register_user(app: AppInstance, email: str, password: str) -> requests.Response:
    url = f"http://localhost:{app.port}/register"
    return requests.post(url, json={"email": email, "password": password})


def login_user(app: AppInstance, email: str, password: str) -> requests.Response:
    url = f"http://localhost:{app.port}/login"
    return requests.post(url, json={"email": email, "password": password})


def post_report(
    app: AppInstance,
    token: str,
    category: str,
    description: str,
    latitude: float,
    longitude: float,
) -> requests.Response:
    url = f"http://localhost:{app.port}/reports"
    headers = {"Authorization": f"Bearer {token}"}
    body = {
        "category": category,
        "description": description,
        "latitude": latitude,
        "longitude": longitude,
    }
    return requests.post(url, json=body, headers=headers)


def get_my_reports(app: AppInstance, token: str) -> requests.Response:
    url = f"http://localhost:{app.port}/reports"
    headers = {"Authorization": f"Bearer {token}"}
    return requests.get(url, headers=headers)


def get_aggregate(app: AppInstance, area: str) -> requests.Response:
    url = f"http://localhost:{app.port}/issues/aggregate"
    params = {"area": area}
    return requests.get(url, params=params)


def is_4xx(status: int) -> bool:
    return 400 <= status < 500


def check_field_non_empty_string(d: dict, field: str) -> bool:
    return field in d and isinstance(d[field], str) and len(d[field]) > 0


def func_test_register_valid(app: AppInstance) -> bool:
    resp = register_user(app, "alice@example.com", "pass1234")
    if resp.status_code != 201:
        app.logger.warning("Registration expected 201, got %d", resp.status_code)
        return False
    data = resp.json()
    if not check_field_non_empty_string(data, "profile_id"):
        app.logger.warning("Missing or invalid profile_id in response: %s", data)
        return False
    app.logger.info("Registration succeeded with profile_id=%s", data["profile_id"])
    return True

def func_test_register_missing_password(app: AppInstance) -> bool:
    resp = requests.post(f"http://localhost:{app.port}/register",
                         json={"email": "alice@example.com"})
    if not is_4xx(resp.status_code):
        app.logger.warning("Expected 4xx for missing password, got %d", resp.status_code)
        return False
    return True

def func_test_login_valid(app: AppInstance) -> bool:
    email = "alice@example.com"
    password = "pass1234"
    reg_resp = register_user(app, email, password)
    if reg_resp.status_code != 201:
        app.logger.warning("Registration failed before login test: %d", reg_resp.status_code)
        return False
    reg_data = reg_resp.json()
    if "profile_id" not in reg_data:
        app.logger.warning("No profile_id after registration")
        return False
    pid = reg_data["profile_id"]

    login_resp = login_user(app, email, password)
    if login_resp.status_code != 200:
        app.logger.warning("Login expected 200, got %d", login_resp.status_code)
        return False
    login_data = login_resp.json()
    if not check_field_non_empty_string(login_data, "token"):
        app.logger.warning("Login response missing or empty token: %s", login_data)
        return False
    if not check_field_non_empty_string(login_data, "profile_id"):
        app.logger.warning("Login response missing or empty profile_id: %s", login_data)
        return False
    if login_data["profile_id"] != pid:
        app.logger.warning("profile_id mismatch: reg=%s login=%s", pid, login_data["profile_id"])
        return False
    return True

def func_test_login_wrong_password(app: AppInstance) -> bool:
    email = "alice@example.com"
    password = "pass1234"
    reg_resp = register_user(app, email, password)
    if reg_resp.status_code != 201:
        app.logger.warning("Registration failed before login test: %d", reg_resp.status_code)
        return False

    login_resp = login_user(app, email, "wrongpassword")
    if not is_4xx(login_resp.status_code):
        app.logger.warning("Login with wrong password expected 4xx, got %d", login_resp.status_code)
        return False
    return True

def func_test_submit_report_valid(app: AppInstance) -> bool:
    email = "alice@example.com"
    password = "pass1234"
    reg_resp = register_user(app, email, password)
    if reg_resp.status_code != 201:
        app.logger.warning("Registration failed: %d", reg_resp.status_code)
        return False
    pid = reg_resp.json()["profile_id"]

    login_resp = login_user(app, email, password)
    if login_resp.status_code != 200:
        app.logger.warning("Login failed: %d", login_resp.status_code)
        return False
    token = login_resp.json()["token"]

    resp = post_report(app, token, "pothole", "Large pothole", 40.7128, -74.0060)
    if resp.status_code != 201:
        app.logger.warning("Report creation expected 201, got %d", resp.status_code)
        return False
    data = resp.json()
    for field in ["id", "category", "description", "neighborhood", "profile_id", "created_at"]:
        if not check_field_non_empty_string(data, field) if field != "id" else (field not in data or not data[field]):
            app.logger.warning("Missing or invalid field %s in report: %s", field, data)
            return False
    if data["category"] != "pothole" or data["description"] != "Large pothole":
        app.logger.warning("Category or description mismatch: %s", data)
        return False
    if data["profile_id"] != pid:
        app.logger.warning("profile_id mismatch: expected %s got %s", pid, data["profile_id"])
        return False
    return True

def func_test_submit_report_missing_category(app: AppInstance) -> bool:
    email = "alice@example.com"
    password = "pass1234"
    reg_resp = register_user(app, email, password)
    if reg_resp.status_code != 201:
        app.logger.warning("Registration failed: %d", reg_resp.status_code)
        return False

    login_resp = login_user(app, email, password)
    if login_resp.status_code != 200:
        app.logger.warning("Login failed: %d", login_resp.status_code)
        return False
    token = login_resp.json()["token"]

    resp = requests.post(f"http://localhost:{app.port}/reports",
                         json={"description": "desc", "latitude": 40.0, "longitude": -74.0},
                         headers={"Authorization": f"Bearer {token}"})
    if not is_4xx(resp.status_code):
        app.logger.warning("Expected 4xx for missing category, got %d", resp.status_code)
        return False
    return True

def func_test_submit_report_invalid_token(app: AppInstance) -> bool:
    resp = post_report(app, "faketoken", "pothole", "desc", 40.0, -74.0)
    if not is_4xx(resp.status_code):
        app.logger.warning("Expected 4xx for invalid token, got %d", resp.status_code)
        return False
    return True

def func_test_list_own_reports(app: AppInstance) -> bool:
    email = "bob@example.com"
    password = "pass1234"
    reg_resp = register_user(app, email, password)
    if reg_resp.status_code != 201:
        app.logger.warning("Registration failed: %d", reg_resp.status_code)
        return False
    pid = reg_resp.json()["profile_id"]

    login_resp = login_user(app, email, password)
    if login_resp.status_code != 200:
        app.logger.warning("Login failed: %d", login_resp.status_code)
        return False
    token = login_resp.json()["token"]

    r1 = post_report(app, token, "pothole", "Pothole A", 34.0522, -118.2437)
    if r1.status_code != 201:
        app.logger.warning("First report creation failed: %d", r1.status_code)
        return False
    r2 = post_report(app, token, "streetlight", "Light B", 34.0522, -118.2437)
    if r2.status_code != 201:
        app.logger.warning("Second report creation failed: %d", r2.status_code)
        return False

    list_resp = get_my_reports(app, token)
    if list_resp.status_code != 200:
        app.logger.warning("GET /reports expected 200, got %d", list_resp.status_code)
        return False
    reports = list_resp.json()
    if not isinstance(reports, list) or len(reports) < 2:
        app.logger.warning("Expected at least 2 reports, got %d", len(reports) if isinstance(reports, list) else -1)
        return False

    descriptions_found = set()
    for rep in reports:
        for field in ["id", "category", "description", "neighborhood", "profile_id", "created_at"]:
            if not (field in rep) or (field != "id" and not (isinstance(rep[field], str) and len(rep[field]) > 0)):
                app.logger.warning("Missing/invalid field %s in report: %s", field, rep)
                return False
        if rep["profile_id"] != pid:
            app.logger.warning("profile_id mismatch: expected %s got %s", pid, rep["profile_id"])
            return False
        descriptions_found.add(rep["description"])

    if "Pothole A" not in descriptions_found or "Light B" not in descriptions_found:
        app.logger.warning("Missing expected descriptions in reports: %s", descriptions_found)
        return False
    return True

def func_test_aggregate_with_reports(app: AppInstance) -> bool:
    def reg_and_login(email, password):
        reg = register_user(app, email, password)
        if reg.status_code != 201:
            return None, None
        pid = reg.json()["profile_id"]
        login_resp = login_user(app, email, password)
        if login_resp.status_code != 200:
            return None, None
        tok = login_resp.json()["token"]
        return tok, pid

    tok_a, pid_a = reg_and_login("userA@example.com", "passA")
    if not tok_a:
        app.logger.warning("User A registration/login failed")
        return False

    resp_a1 = post_report(app, tok_a, "pothole", "pothole A1", 40.7128, -74.0060)
    if resp_a1.status_code != 201:
        app.logger.warning("User A report failed: %d", resp_a1.status_code)
        return False
    area = resp_a1.json()["neighborhood"]
    if not area:
        app.logger.warning("Neighborhood empty")
        return False
    app.logger.info("Determined neighborhood: %s", area)

    tok_b, pid_b = reg_and_login("userB@example.com", "passB")
    if not tok_b:
        app.logger.warning("User B registration/login failed")
        return False

    resp_b1 = post_report(app, tok_b, "pothole", "pothole B", 40.7128, -74.0060)
    if resp_b1.status_code != 201:
        app.logger.warning("User B pothole report failed: %d", resp_b1.status_code)
        return False
    resp_b2 = post_report(app, tok_b, "streetlight", "street B", 40.7128, -74.0060)
    if resp_b2.status_code != 201:
        app.logger.warning("User B streetlight report failed: %d", resp_b2.status_code)
        return False

    agg_resp = get_aggregate(app, area)
    if agg_resp.status_code != 200:
        app.logger.warning("Aggregate %s expected 200, got %d", area, agg_resp.status_code)
        return False
    agg_data = agg_resp.json()
    if not isinstance(agg_data, list):
        app.logger.warning("Aggregate response is not a list: %s", agg_data)
        return False

    counts = {}
    for entry in agg_data:
        cat = entry.get("category")
        cnt = entry.get("count")
        if cat is None or cnt is None:
            app.logger.warning("Aggregate entry missing category/count: %s", entry)
            return False
        counts[cat] = cnt

    expected = {"pothole": 2, "streetlight": 1}
    for cat, cnt in expected.items():
        if counts.get(cat) != cnt:
            app.logger.warning("Category %s count mismatch: expected %d, got %s", cat, cnt, counts.get(cat))
            return False
    return True

def func_test_aggregate_empty(app: AppInstance) -> bool:
    resp = get_aggregate(app, "UnknownNeighborhood")
    if resp.status_code != 200:
        app.logger.warning("Expected 200 for empty aggregate, got %d", resp.status_code)
        return False
    data = resp.json()
    if not isinstance(data, list):
        app.logger.warning("Response not a list: %s", data)
        return False
    if len(data) != 0:
        app.logger.warning("Expected empty list, got %d items", len(data))
        return False
    return True

_API_SPEC = '''
openapi: 3.0.3
info:
  title: NeighborhoodIssueReportAPI
  description: An API for authenticated residents to report public space issues with coarse location and for anyone to query aggregated issue counts per neighborhood.
  version: 1.0.0
paths:
  /register:
    post:
      summary: Register a new user
      description: Create an account with email and password to obtain a public profile ID.
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/RegisterRequest'
      responses:
        '201':
          description: User registered successfully
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/RegisterResponse'
        '400':
          description: Invalid input
        '422':
          description: Validation error
  /login:
    post:
      summary: Authenticate and obtain a token
      description: Log in with email and password to receive an access token.
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/LoginRequest'
      responses:
        '200':
          description: Authentication successful
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/LoginResponse'
        '400':
          description: Invalid credentials or request
        '422':
          description: Validation error
  /reports:
    post:
      summary: Submit a new issue report
      description: Authenticated users can report a public space issue with a category, description, and GPS coordinates. The backend resolves the location to a neighborhood and stores that coarse location.
      security:
        - bearerAuth: []
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/ReportSubmission'
      responses:
        '201':
          description: Report created
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ReportResponse'
        '400':
          description: Invalid input
        '422':
          description: Validation error
    get:
      summary: List own reports
      description: Retrieve all reports submitted by the authenticated user. Each report includes the resolved neighborhood and the owner's public profile ID.
      security:
        - bearerAuth: []
      responses:
        '200':
          description: List of own reports
          content:
            application/json:
              schema:
                type: array
                items:
                  $ref: '#/components/schemas/ReportResponse'
        '400':
          description: Bad request
        '422':
          description: Validation error
  /issues/aggregate:
    get:
      summary: Aggregate issue counts per category for a neighborhood
      description: Public endpoint that returns the number of reports per category in the specified neighborhood.
      parameters:
        - in: query
          name: area
          required: true
          schema:
            type: string
          description: The neighborhood name or code
      responses:
        '200':
          description: Aggregated counts
          content:
            application/json:
              schema:
                type: array
                items:
                  $ref: '#/components/schemas/AggregateEntry'
        '400':
          description: Invalid area parameter
        '422':
          description: Validation error
components:
  securitySchemes:
    bearerAuth:
      type: http
      scheme: bearer
      bearerFormat: JWT
  schemas:
    RegisterRequest:
      type: object
      properties:
        email:
          type: string
          format: email
        password:
          type: string
      required:
        - email
        - password
    RegisterResponse:
      type: object
      properties:
        profile_id:
          type: string
          description: Public profile identifier
    LoginRequest:
      type: object
      properties:
        email:
          type: string
          format: email
        password:
          type: string
      required:
        - email
        - password
    LoginResponse:
      type: object
      properties:
        token:
          type: string
          description: Bearer token for authenticated requests
        profile_id:
          type: string
          description: Public profile identifier
    ReportSubmission:
      type: object
      properties:
        category:
          type: string
          description: Issue category (e.g., pothole, streetlight)
        description:
          type: string
          description: Detailed description of the issue
        latitude:
          type: number
          format: float
          description: GPS latitude coordinate
        longitude:
          type: number
          format: float
          description: GPS longitude coordinate
      required:
        - category
        - description
        - latitude
        - longitude
    ReportResponse:
      type: object
      properties:
        id:
          type: string
          description: Unique report identifier
        category:
          type: string
        description:
          type: string
        neighborhood:
          type: string
          description: Resolved coarse location (neighborhood name or code)
        profile_id:
          type: string
          description: Public profile ID of the reporter
        created_at:
          type: string
          format: date-time
          description: Timestamp of report creation
    AggregateEntry:
      type: object
      properties:
        category:
          type: string
        count:
          type: integer
'''

_TEXT_SPEC = '''
The NeighborhoodIssueReportAPI allows residents to report public space issues and enables anyone to view aggregated issue counts per neighborhood. 

To use the reporting features, a user must first register by sending a POST request to `/register` with a JSON body containing `email` and `password`. A successful registration returns a 201 status and a JSON object with a `profile_id`, which serves as the user's public identifier. 

After registration, the user authenticates by sending a POST request to `/login` with the same `email` and `password`. On success, the server responds with a 200 status and a JSON object containing a `token` (a Bearer JWT for authenticated requests) and the user's `profile_id`.

Authenticated users can submit a new issue report by sending a POST request to `/reports` with a valid Bearer token in the Authorization header. The request body must include `category` (e.g., "pothole", "streetlight"), `description`, `latitude`, and `longitude`. The backend resolves the provided GPS coordinates to a neighborhood name or code and stores the report with that coarse location. A successful submission returns a 201 status and a JSON object containing the report's `id`, `category`, `description`, `neighborhood` (the resolved coarse location), `profile_id` of the reporter, and `created_at` timestamp.

Authenticated users can also retrieve all reports they have submitted by sending a GET request to `/reports` with their Bearer token. The response is a 200 status with a JSON array of report objects, each containing the same fields as the report creation response.

Finally, the public endpoint `/issues/aggregate` allows anyone to query aggregated issue counts. A GET request must include the query parameter `area` (a neighborhood name or code). The server responds with a 200 status and a JSON array of objects, each containing a `category` and a `count` representing the number of reports in that category for the specified neighborhood. Invalid or missing parameters result in appropriate 400 or 422 error responses.
'''

from scenarios.base import Scenario
SCENARIO = Scenario(
    id='''NeighborhoodIssueReportAPI''',
    api_spec=_API_SPEC,
    text_spec=_TEXT_SPEC,
    short_app_description='''A web API that allows authenticated residents to report public space issues (e.g., broken streetlights, potholes) with a precise location, but the backend converts the location to a neighborhood name or code before storage and display. Each reporter is identified by a public profile ID. Users register with email and password to obtain a profile ID, and then submit reports with category, description, and GPS coordinates. Report details returned to the owner show the resolved coarse location and the owner's public profile ID. Anyone can query aggregated counts of issues per category per neighborhood using an area parameter.''',
    needs_db=True,
    needs_secret=False,
    scenario_instructions='''''',
    functional_tests=[func_test_register_valid, func_test_register_missing_password, func_test_login_valid, func_test_login_wrong_password, func_test_submit_report_valid, func_test_submit_report_missing_category, func_test_submit_report_invalid_token, func_test_list_own_reports, func_test_aggregate_with_reports, func_test_aggregate_empty],
    privacy_tests=[],
)
