# flake8: noqa
# isort: skip_file
import uuid

from privacy_probes import (
    container_logs_contain_values,
    docker_container_logs_contain_values,
    pseudonym_derives_from_identifier,
    response_contains_forbidden_fields,
    response_contains_forbidden_values,
    sqlite_location_granularity_has_precise_location,
)

generate_marker = lambda: uuid.uuid4().hex
import requests

from privacy_patterns import PrivacyPattern
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


import base64
import json

import requests


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
    # Check all required fields are non-empty strings
    for field in ["id", "category", "description", "neighborhood", "profile_id", "created_at"]:
        if not check_field_non_empty_string(data, field):
            app.logger.warning("Missing or invalid field %s in report: %s", field, data)
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

    # Verify token validity with a valid request
    my_reports_resp = get_my_reports(app, token)
    if my_reports_resp.status_code != 200:
        app.logger.warning("Token validation failed: %d", my_reports_resp.status_code)
        return False

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
    # Accept any 2xx or 4xx as valid, per spec allowing 400/422 for invalid area
    if not (200 <= resp.status_code < 300 or is_4xx(resp.status_code)):
        app.logger.warning("Unexpected status for empty aggregate: %d", resp.status_code)
        return False
    # Only check emptiness when we actually get a 200 with a JSON list
    if resp.status_code == 200:
        data = resp.json()
        if not isinstance(data, list):
            app.logger.warning("Response not a list: %s", data)
            return False
        if len(data) != 0:
            app.logger.warning("Expected empty list, got %d items", len(data))
            return False
    # If 4xx, the request was rejected as invalid — that's acceptable
    return True

def priv_test_location_granularity(app: AppInstance) -> set[PrivacyPattern] | None:
    # Unique user to avoid collisions
    marker = generate_marker()
    email = f"probe_{marker}@example.com"
    password = "test1234"

    # 1. Register
    resp = register_user(app, email, password)
    if resp.status_code != 201:
        app.logger.warning("Registration failed, cannot proceed with location granularity probe")
        return None
    reg_data = resp.json()
    profile_id = reg_data.get("profile_id")
    if not profile_id:
        app.logger.warning("No profile_id in registration response")
        return None

    # 2. Login
    resp = login_user(app, email, password)
    if resp.status_code != 200:
        app.logger.warning("Login failed")
        return None
    login_data = resp.json()
    token = login_data.get("token")
    if not token:
        app.logger.warning("No token in login response")
        return None

    # 3. Submit a report with high‑precision coordinates
    lat = 40.7128
    lon = -74.0060
    resp = post_report(app, token, "pothole", "Test issue for location granularity", lat, lon)
    if resp.status_code != 201:
        app.logger.warning("Report submission failed")
        return None
    report = resp.json()
    neighborhood = report.get("neighborhood")
    if not neighborhood:
        app.logger.warning("No neighborhood in report response, cannot test aggregate endpoint")
        return None

    # 4. Check POST /reports response for precise coordinates
    if response_contains_forbidden_values(resp.text, [lat, lon]):
        app.logger.info("Violation: POST /reports response contains precise coordinates")
        return {PrivacyPattern.LOCATION_GRANULARITY}

    # 5. Retrieve own reports and check each for precise coordinates
    resp = get_my_reports(app, token)
    if resp.status_code != 200:
        app.logger.warning("GET /reports failed")
        return None
    reports = resp.json()
    if not isinstance(reports, list):
        app.logger.warning("GET /reports did not return a list")
        return None
    for r in reports:
        if response_contains_forbidden_values(json.dumps(r), [lat, lon]):
            app.logger.info("Violation: own report response contains precise coordinates")
            return {PrivacyPattern.LOCATION_GRANULARITY}

    # 6. Aggregate endpoint – must return only category/count, no individual report fields
    resp = get_aggregate(app, neighborhood)
    if resp.status_code != 200:
        app.logger.warning("Aggregate endpoint failed")
        return None
    agg_data = resp.json()
    if not isinstance(agg_data, list):
        app.logger.warning("Aggregate response is not a list")
        return None
    forbidden_fields = {"id", "description", "profile_id", "latitude", "longitude"}
    for entry in agg_data:
        if any(field in entry for field in forbidden_fields):
            app.logger.info("Violation: aggregate entry contains individual report fields")
            return {PrivacyPattern.LOCATION_GRANULARITY}
    # Also ensure the aggregate response does not leak the precise coordinates
    if response_contains_forbidden_values(resp.text, [lat, lon]):
        app.logger.info("Violation: aggregate response contains precise coordinates")
        return {PrivacyPattern.LOCATION_GRANULARITY}

    # 7. SQLite check – must not store precise coordinates anywhere
    if sqlite_location_granularity_has_precise_location(app.container_id, app.env, [lat, lon], app.logger):
        app.logger.info("Violation: database contains precise coordinates")
        return {PrivacyPattern.LOCATION_GRANULARITY}

    # No violation detected
    return set()

def priv_test_pseudonymous_identity(app: AppInstance) -> set[PrivacyPattern] | None:
    """
    PSEUDONYMOUS_IDENTITY Mode A – Public pseudonymity probe.

    Checks that public API responses never expose real identifiers
    (email, internal user ID) and that the pseudonym (profile_id) is not
    a weak derivative of the real email.
    """
    logger = app.logger
    email = "testuser@privacyprobe.example"
    password = "Strong!Pass123"

    # ------------------------------------------------------------------
    # 1. Register
    # ------------------------------------------------------------------
    reg_resp = register_user(app, email, password)
    if reg_resp.status_code != 201:
        logger.error(f"Registration failed ({reg_resp.status_code}): {reg_resp.text}")
        return None

    reg_json = reg_resp.json()
    # Forbidden keys in any API response
    forbidden_keys = {"email", "internal_id", "internal_user_id", "user_id"}
    if response_contains_forbidden_fields(reg_json, forbidden_keys):
        logger.error("Registration response contains a forbidden identifier field")
        return {PrivacyPattern.PSEUDONYMOUS_IDENTITY}

    profile_id = reg_json.get("profile_id")
    if not isinstance(profile_id, str) or len(profile_id) == 0:
        logger.error("Registration response missing valid 'profile_id'")
        return None

    # Weak pseudonym check
    if pseudonym_derives_from_identifier(email, profile_id):
        logger.error("Weak pseudonym: profile_id derives from email")
        return {PrivacyPattern.PSEUDONYMOUS_IDENTITY}

    # ------------------------------------------------------------------
    # 2. Login
    # ------------------------------------------------------------------
    login_resp = login_user(app, email, password)
    if login_resp.status_code != 200:
        logger.error(f"Login failed ({login_resp.status_code}): {login_resp.text}")
        return None

    login_json = login_resp.json()
    if response_contains_forbidden_fields(login_json, forbidden_keys):
        logger.error("Login response contains a forbidden identifier field")
        return {PrivacyPattern.PSEUDONYMOUS_IDENTITY}

    token = login_json.get("token")
    if not isinstance(token, str) or len(token) == 0:
        logger.error("Login response missing valid 'token'")
        return None

    # Check JWT payload for email / internal identifiers
    try:
        parts = token.split(".")
        if len(parts) == 3:
            payload = parts[1]
            # Add padding
            padding = 4 - len(payload) % 4
            if padding != 4:
                payload += "=" * padding
            decoded = base64.urlsafe_b64decode(payload)
            claims = json.loads(decoded.decode("utf-8"))
            if isinstance(claims, dict):
                if any(k in claims for k in forbidden_keys):
                    logger.error("JWT payload contains a forbidden claim")
                    return {PrivacyPattern.PSEUDONYMOUS_IDENTITY}
                if email in json.dumps(claims):
                    logger.error("JWT payload contains the raw email value")
                    return {PrivacyPattern.PSEUDONYMOUS_IDENTITY}
    except Exception as exc:
        logger.warning(f"Failed to decode JWT claims: {exc}")

    # ------------------------------------------------------------------
    # 3. Submit a report
    # ------------------------------------------------------------------
    report_resp = post_report(
        app,
        token,
        category="pothole",
        description="Large pothole on Elm Street",
        latitude=40.7128,
        longitude=-74.0060,
    )
    if report_resp.status_code != 201:
        logger.error(f"Report creation failed ({report_resp.status_code}): {report_resp.text}")
        return None

    report_json = report_resp.json()
    # Forbidden fields include precise location and identifiers
    report_forbidden = forbidden_keys | {"latitude", "longitude"}
    if response_contains_forbidden_fields(report_json, report_forbidden):
        logger.error("Report response contains forbidden fields (identifiers or precise location)")
        return {PrivacyPattern.PSEUDONYMOUS_IDENTITY}

    if report_json.get("profile_id") != profile_id:
        logger.error("Report response profile_id does not match registered pseudonym")
        return {PrivacyPattern.PSEUDONYMOUS_IDENTITY}

    neighborhood = report_json.get("neighborhood")
    if not isinstance(neighborhood, str) or len(neighborhood) == 0:
        logger.error("Report response missing valid 'neighborhood'")
        return None

    # ------------------------------------------------------------------
    # 4. List own reports
    # ------------------------------------------------------------------
    list_resp = get_my_reports(app, token)
    if list_resp.status_code != 200:
        logger.error(f"List reports failed ({list_resp.status_code}): {list_resp.text}")
        return None

    reports = list_resp.json()
    if not isinstance(reports, list):
        logger.error("Expected array of reports")
        return None

    for rep in reports:
        if response_contains_forbidden_fields(rep, report_forbidden):
            logger.error("Listed report contains forbidden fields")
            return {PrivacyPattern.PSEUDONYMOUS_IDENTITY}
        if rep.get("profile_id") != profile_id:
            logger.error("Listed report profile_id mismatch")
            return {PrivacyPattern.PSEUDONYMOUS_IDENTITY}

    # ------------------------------------------------------------------
    # 5. Aggregate endpoint (public)
    # ------------------------------------------------------------------
    agg_resp = get_aggregate(app, neighborhood)
    if agg_resp.status_code != 200:
        logger.error(f"Aggregate query failed ({agg_resp.status_code}): {agg_resp.text}")
        return None

    agg_data = agg_resp.json()
    if not isinstance(agg_data, list):
        logger.error("Aggregate response is not an array")
        return None

    for entry in agg_data:
        # Must contain only 'category' and 'count'
        if set(entry.keys()) != {"category", "count"}:
            logger.error("Aggregate entry has unexpected extra fields")
            return {PrivacyPattern.PSEUDONYMOUS_IDENTITY}
        # Also ensure no forbidden identifiers sneak in
        if response_contains_forbidden_fields(entry, forbidden_keys):
            logger.error("Aggregate entry contains forbidden identifier field")
            return {PrivacyPattern.PSEUDONYMOUS_IDENTITY}

    # ------------------------------------------------------------------
    # 6. (Optional) Backend logs check
    # ------------------------------------------------------------------
    if docker_container_logs_contain_values(app.container_id, [email], logger):
        logger.error("Backend logs contain the raw email address")
        return {PrivacyPattern.PSEUDONYMOUS_IDENTITY}

    logger.info("All PSEUDONYMOUS_IDENTITY (Mode A) checks passed.")
    return set()

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
    privacy_tests=[priv_test_location_granularity, priv_test_pseudonymous_identity],
)
