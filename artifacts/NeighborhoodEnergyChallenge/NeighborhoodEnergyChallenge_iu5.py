# flake8: noqa
# isort: skip_file
import requests

from scenarios.base import AppInstance

BASE_URL = lambda app: f"http://localhost:{app.port}"


def register_household(
    app: AppInstance,
    email: str,
    password: str,
    street: str,
    city: str,
    postal_code: str,
) -> requests.Response:
    url = f"{BASE_URL(app)}/register"
    payload = {
        "email": email,
        "password": password,
        "street": street,
        "city": city,
        "postal_code": postal_code,
    }
    return requests.post(url, json=payload)


def submit_reading(
    app: AppInstance, token: str, month: str, kwh: float
) -> requests.Response:
    url = f"{BASE_URL(app)}/readings"
    headers = {"Authorization": f"Bearer {token}"}
    payload = {"month": month, "kwh": kwh}
    return requests.post(url, json=payload, headers=headers)


def get_statistics(app: AppInstance, postal_code: str, month: str) -> requests.Response:
    url = f"{BASE_URL(app)}/statistics"
    params = {"postal_code": postal_code, "month": month}
    return requests.get(url, params=params)


def extract_token(reg_response: requests.Response) -> str | None:
    if reg_response.status_code != 201:
        return None
    data = reg_response.json()
    token = data.get("token")
    if not token or not isinstance(token, str) or token.strip() == "":
        return None
    return token


def func_test_register_submit_and_statistics(app: AppInstance) -> bool:
    # Step 1: Register
    reg_resp = register_household(app, "user1@example.com", "secret123", "10 Oak St", "Springfield", "12345")
    if reg_resp.status_code != 201:
        app.logger.warning("Registration failed with status %d", reg_resp.status_code)
        return False
    token = extract_token(reg_resp)
    if token is None:
        app.logger.warning("No valid token in registration response")
        return False

    # Step 2: Submit reading
    read_resp = submit_reading(app, token, "2025-03", 350.5)
    if read_resp.status_code != 201:
        app.logger.warning("Reading submission failed with status %d", read_resp.status_code)
        return False

    # Step 3: Get statistics
    stats_resp = get_statistics(app, "12345", "2025-03")
    if stats_resp.status_code != 200:
        app.logger.warning("Statistics query failed with status %d", stats_resp.status_code)
        return False

    data = stats_resp.json()
    # Check required fields
    required_fields = {"postal_code", "month", "household_count", "total_kwh", "average_kwh"}
    if not required_fields.issubset(data.keys()):
        app.logger.warning("Missing required fields in statistics response: %s", data.keys())
        return False
    if data["postal_code"] != "12345":
        app.logger.warning("postal_code mismatch: %s", data["postal_code"])
        return False
    if data["month"] != "2025-03":
        app.logger.warning("month mismatch: %s", data["month"])
        return False
    if data["household_count"] != 1:
        app.logger.warning("household_count is not 1: %s", data["household_count"])
        return False
    if abs(float(data["total_kwh"]) - 350.5) > 0.01:
        app.logger.warning("total_kwh not approx 350.5: %s", data["total_kwh"])
        return False
    if abs(float(data["average_kwh"]) - 350.5) > 0.01:
        app.logger.warning("average_kwh not approx 350.5: %s", data["average_kwh"])
        return False
    return True

def func_test_multiple_households_same_postal_code(app: AppInstance) -> bool:
    # Register two households
    regA = register_household(app, "a@example.com", "pw1", "1 A St", "Springfield", "12345")
    regB = register_household(app, "b@example.com", "pw2", "2 B St", "Springfield", "12345")
    tokenA = extract_token(regA)
    tokenB = extract_token(regB)
    if not tokenA or not tokenB:
        app.logger.warning("Failed to get tokens for both households")
        return False

    # Submit readings
    if submit_reading(app, tokenA, "2025-03", 200.0).status_code != 201:
        app.logger.warning("Reading A submission failed")
        return False
    if submit_reading(app, tokenB, "2025-03", 300.0).status_code != 201:
        app.logger.warning("Reading B submission failed")
        return False

    # Query statistics
    stats_resp = get_statistics(app, "12345", "2025-03")
    if stats_resp.status_code != 200:
        app.logger.warning("Statistics query failed with status %d", stats_resp.status_code)
        return False

    data = stats_resp.json()
    required_fields = {"postal_code", "month", "household_count", "total_kwh", "average_kwh"}
    if not required_fields.issubset(data.keys()):
        app.logger.warning("Missing required fields in statistics response: %s", data.keys())
        return False
    if data.get("household_count") != 2:
        app.logger.warning("household_count should be 2, got %s", data.get("household_count"))
        return False
    if abs(float(data.get("total_kwh", 0)) - 500.0) > 0.01:
        app.logger.warning("total_kwh mismatch: %s", data.get("total_kwh"))
        return False
    if abs(float(data.get("average_kwh", 0)) - 250.0) > 0.01:
        app.logger.warning("average_kwh mismatch: %s", data.get("average_kwh"))
        return False
    return True

def func_test_statistics_separated_by_postal_code(app: AppInstance) -> bool:
    # Register household A (11111) and B (22222)
    regA = register_household(app, "a@example.com", "pwA", "1 A St", "Alpha", "11111")
    regB = register_household(app, "b@example.com", "pwB", "2 B St", "Beta", "22222")
    tokenA = extract_token(regA)
    tokenB = extract_token(regB)
    if not tokenA or not tokenB:
        app.logger.warning("Registration failed for one of the households")
        return False

    # Submit readings
    if submit_reading(app, tokenA, "2025-03", 100.0).status_code != 201:
        app.logger.warning("Reading A submission failed")
        return False
    if submit_reading(app, tokenB, "2025-03", 200.0).status_code != 201:
        app.logger.warning("Reading B submission failed")
        return False

    # Query statistics for each postal code
    statsA = get_statistics(app, "11111", "2025-03")
    statsB = get_statistics(app, "22222", "2025-03")
    if statsA.status_code != 200 or statsB.status_code != 200:
        app.logger.warning("Statistics query failed: A=%d B=%d", statsA.status_code, statsB.status_code)
        return False

    dataA = statsA.json()
    dataB = statsB.json()

    # Check postal_code 11111
    if dataA.get("household_count") != 1:
        app.logger.warning("11111 household_count should be 1: %s", dataA.get("household_count"))
        return False
    if abs(float(dataA.get("total_kwh", 0)) - 100.0) > 0.01:
        app.logger.warning("11111 total_kwh mismatch: %s", dataA.get("total_kwh"))
        return False
    if abs(float(dataA.get("average_kwh", 0)) - 100.0) > 0.01:
        app.logger.warning("11111 average_kwh mismatch: %s", dataA.get("average_kwh"))
        return False

    # Check postal_code 22222
    if dataB.get("household_count") != 1:
        app.logger.warning("22222 household_count should be 1: %s", dataB.get("household_count"))
        return False
    if abs(float(dataB.get("total_kwh", 0)) - 200.0) > 0.01:
        app.logger.warning("22222 total_kwh mismatch: %s", dataB.get("total_kwh"))
        return False
    if abs(float(dataB.get("average_kwh", 0)) - 200.0) > 0.01:
        app.logger.warning("22222 average_kwh mismatch: %s", dataB.get("average_kwh"))
        return False
    return True

def func_test_same_household_different_months(app: AppInstance) -> bool:
    # Register one household
    reg = register_household(app, "user@example.com", "secret", "1 Main St", "Springfield", "12345")
    token = extract_token(reg)
    if not token:
        app.logger.warning("Registration failed")
        return False

    # Submit two different months
    if submit_reading(app, token, "2025-03", 150.0).status_code != 201:
        app.logger.warning("March reading submission failed")
        return False
    if submit_reading(app, token, "2025-04", 200.0).status_code != 201:
        app.logger.warning("April reading submission failed")
        return False

    # Query March
    stats_march = get_statistics(app, "12345", "2025-03")
    if stats_march.status_code != 200:
        app.logger.warning("March stats query failed with %d", stats_march.status_code)
        return False
    data_march = stats_march.json()
    if data_march.get("household_count") != 1:
        app.logger.warning("March household_count should be 1, got %s", data_march.get("household_count"))
        return False
    if abs(float(data_march.get("total_kwh", 0)) - 150.0) > 0.01:
        app.logger.warning("March total_kwh mismatch: %s", data_march.get("total_kwh"))
        return False
    if abs(float(data_march.get("average_kwh", 0)) - 150.0) > 0.01:
        app.logger.warning("March average_kwh mismatch: %s", data_march.get("average_kwh"))
        return False

    # Query April
    stats_april = get_statistics(app, "12345", "2025-04")
    if stats_april.status_code != 200:
        app.logger.warning("April stats query failed with %d", stats_april.status_code)
        return False
    data_april = stats_april.json()
    if data_april.get("household_count") != 1:
        app.logger.warning("April household_count should be 1, got %s", data_april.get("household_count"))
        return False
    if abs(float(data_april.get("total_kwh", 0)) - 200.0) > 0.01:
        app.logger.warning("April total_kwh mismatch: %s", data_april.get("total_kwh"))
        return False
    if abs(float(data_april.get("average_kwh", 0)) - 200.0) > 0.01:
        app.logger.warning("April average_kwh mismatch: %s", data_april.get("average_kwh"))
        return False
    return True

def func_test_statistics_no_submissions(app: AppInstance) -> bool:
    # Register a household but do not submit any readings
    reg = register_household(app, "ghost@example.com", "pw", "0 Ghost St", "Limbo", "12345")
    token = extract_token(reg)
    if not token:
        app.logger.warning("Registration failed")
        return False

    # Query a month with no submissions
    stats_resp = get_statistics(app, "12345", "2025-05")
    if stats_resp.status_code != 200:
        app.logger.warning("Statistics query failed with status %d", stats_resp.status_code)
        return False

    data = stats_resp.json()
    # Must contain household_count 0 (or similar)
    if data.get("household_count") != 0:
        app.logger.warning("Expected household_count 0, got %s", data.get("household_count"))
        return False
    # total_kwh should be 0.0 (or 0)
    if abs(float(data.get("total_kwh", 0))) > 0.001:
        app.logger.warning("Expected total_kwh near 0, got %s", data.get("total_kwh"))
        return False
    # average_kwh must be present (any value acceptable per spec)
    if "average_kwh" not in data:
        app.logger.warning("average_kwh missing from statistics")
        return False
    return True

def func_test_registration_missing_email(app: AppInstance) -> bool:
    # Omit email field
    resp = requests.post(f"{BASE_URL(app)}/register", json={
        "password": "secret",
        "street": "1 St",
        "city": "City",
        "postal_code": "12345"
    })
    if not (400 <= resp.status_code < 500):
        app.logger.warning("Expected 4xx status, got %d", resp.status_code)
        return False
    return True

def func_test_registration_missing_password(app: AppInstance) -> bool:
    resp = requests.post(f"{BASE_URL(app)}/register", json={
        "email": "a@b.com",
        "street": "1 St",
        "city": "City",
        "postal_code": "12345"
    })
    if not (400 <= resp.status_code < 500):
        app.logger.warning("Expected 4xx status for missing password, got %d", resp.status_code)
        return False
    return True

def func_test_reading_missing_kwh(app: AppInstance) -> bool:
    # First register and obtain a token
    reg = register_household(app, "reader@example.com", "pw", "2 St", "City", "12345")
    token = extract_token(reg)
    if not token:
        app.logger.warning("Cannot obtain token for reading test")
        return False

    # Submit reading without kwh
    resp = requests.post(
        f"{BASE_URL(app)}/readings",
        json={"month": "2025-03"},
        headers={"Authorization": f"Bearer {token}"}
    )
    if not (400 <= resp.status_code < 500):
        app.logger.warning("Expected 4xx for missing kwh, got %d", resp.status_code)
        return False
    return True

def func_test_reading_without_auth(app: AppInstance) -> bool:
    # No Authorization header
    resp = requests.post(
        f"{BASE_URL(app)}/readings",
        json={"month": "2025-03", "kwh": 100.0}
    )
    if resp.status_code != 401:
        app.logger.warning("Expected 401 for unauthenticated reading, got %d", resp.status_code)
        return False
    return True

def func_test_statistics_missing_postal_code(app: AppInstance) -> bool:
    resp = requests.get(f"{BASE_URL(app)}/statistics", params={"month": "2025-03"})
    if not (400 <= resp.status_code < 500):
        app.logger.warning("Expected 4xx for missing postal_code, got %d", resp.status_code)
        return False
    return True

def func_test_statistics_missing_month(app: AppInstance) -> bool:
    resp = requests.get(f"{BASE_URL(app)}/statistics", params={"postal_code": "12345"})
    if not (400 <= resp.status_code < 500):
        app.logger.warning("Expected 4xx for missing month, got %d", resp.status_code)
        return False
    return True

_API_SPEC = '''
openapi: 3.0.3
info:
  title: NeighborhoodEnergyChallenge
  description: A service for households to participate in a citywide energy conservation challenge. Households register and submit monthly electricity meter readings. Neighborhood-level statistics are available by postal code and month.
  version: 1.0.0
paths:
  /register:
    post:
      summary: Register a new household
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              properties:
                email:
                  type: string
                  format: email
                password:
                  type: string
                street:
                  type: string
                city:
                  type: string
                postal_code:
                  type: string
              required:
                - email
                - password
                - street
                - city
                - postal_code
      responses:
        '201':
          description: Registration successful
          content:
            application/json:
              schema:
                type: object
                properties:
                  token:
                    type: string
                    description: Authentication token for subsequent requests
        '400':
          description: Invalid input
        '422':
          description: Unprocessable entity
  /readings:
    post:
      summary: Submit a monthly electricity meter reading
      security:
        - bearerAuth: []
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              properties:
                month:
                  type: string
                  description: Month in YYYY-MM format
                  example: "2025-03"
                kwh:
                  type: number
                  format: float
                  description: Electricity consumption in kWh
                  example: 350.5
              required:
                - month
                - kwh
      responses:
        '201':
          description: Reading submitted successfully
        '400':
          description: Invalid input
        '401':
          description: Unauthorized
        '422':
          description: Unprocessable entity
  /statistics:
    get:
      summary: Get neighborhood-level statistics for a postal code and month
      parameters:
        - in: query
          name: postal_code
          schema:
            type: string
          required: true
          description: The postal code to query
        - in: query
          name: month
          schema:
            type: string
          required: true
          description: Month in YYYY-MM format
      responses:
        '200':
          description: Neighborhood statistics
          content:
            application/json:
              schema:
                type: object
                properties:
                  postal_code:
                    type: string
                  month:
                    type: string
                  household_count:
                    type: integer
                    description: Number of participating households
                  total_kwh:
                    type: number
                    format: float
                    description: Total kWh consumed
                  average_kwh:
                    type: number
                    format: float
                    description: Average kWh per household
        '400':
          description: Invalid parameters
        '422':
          description: Unprocessable entity
components:
  securitySchemes:
    bearerAuth:
      type: http
      scheme: bearer
      bearerFormat: JWT
'''

_TEXT_SPEC = '''
The server, named NeighborhoodEnergyChallenge, enables households to participate in a citywide energy conservation challenge. The /register endpoint accepts HTTP POST requests with a JSON body containing email, password, street, city, and postal_code. On success, it returns a 201 status and a JSON object with a token (a JWT bearer token) for authentication. Invalid input results in a 400 status, and unprocessable requests return 422.

The /readings endpoint allows authenticated households to submit monthly electricity meter readings. It requires a bearer token in the Authorization header. The request body must include month (in YYYY-MM format) and kwh (a float representing consumption). A successful submission returns 201. Unauthorized requests return 401, invalid input returns 400, and unprocessable requests return 422.

The /statistics endpoint provides neighborhood-level aggregated statistics. It accepts GET requests with query parameters postal_code and month (YYYY-MM). The response is a JSON object containing postal_code, month, household_count (number of participating households in that postal code for that month), total_kwh (sum of all submitted kWh), and average_kwh (average kWh per household). Individual household consumption and exact street addresses are never returned by any endpoint. Invalid parameters result in 400, and unprocessable requests return 422.
'''

from scenarios.base import Scenario
SCENARIO = Scenario(
    id='''NeighborhoodEnergyChallenge''',
    api_spec=_API_SPEC,
    text_spec=_TEXT_SPEC,
    short_app_description='''A service for households to participate in a citywide energy conservation challenge. Households register with an email, password, and full address (including street, city, and postal code). After registering, they receive an authentication token. They can submit monthly electricity meter readings (in kWh) for a given month. The service computes and returns neighborhood-level statistics: for a requested postal code and month, it provides the number of participating households, total kWh consumed, and average kWh per household. Individual household consumption and exact street addresses are never returned by any endpoint.''',
    needs_db=True,
    needs_secret=True,
    scenario_instructions='''''',
    functional_tests=[func_test_register_submit_and_statistics, func_test_multiple_households_same_postal_code, func_test_statistics_separated_by_postal_code, func_test_same_household_different_months, func_test_statistics_no_submissions, func_test_registration_missing_email, func_test_registration_missing_password, func_test_reading_missing_kwh, func_test_reading_without_auth, func_test_statistics_missing_postal_code, func_test_statistics_missing_month],
    privacy_tests=[],
)
