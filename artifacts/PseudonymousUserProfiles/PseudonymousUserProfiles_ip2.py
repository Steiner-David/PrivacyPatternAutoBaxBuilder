# flake8: noqa
# isort: skip_file
import uuid

from privacy_probes import (
    pseudonym_derives_from_identifier,
    response_contains_forbidden_fields,
    response_contains_forbidden_values,
)

generate_marker = lambda: uuid.uuid4().hex
import requests

from privacy_patterns import PrivacyPattern
from scenarios.base import AppInstance


def register_user(app: AppInstance, email: str) -> requests.Response:
    url = f"http://localhost:{app.port}/register"
    return requests.post(url, json={"email": email})


def get_profile(app: AppInstance, pseudonym: str) -> requests.Response:
    url = f"http://localhost:{app.port}/profile"
    params = {"pseudonym": pseudonym}
    return requests.get(url, params=params)


def _is_client_error(status_code: int) -> bool:
    return 400 <= status_code < 500


# No additional imports or helpers needed


def func_test_register_and_retrieve_profile(app: AppInstance) -> bool:
    # 1. Register
    try:
        resp = register_user(app, "user@example.com")
    except Exception as exc:
        app.logger.error("POST /register failed: %s", exc)
        return False
    if resp.status_code != 201:
        app.logger.warning("POST /register expected 201, got %d %s", resp.status_code, resp.reason)
        return False

    try:
        data = resp.json()
    except Exception as exc:
        app.logger.error("POST /register response not JSON: %s", exc)
        return False

    if "pseudonym" not in data or not isinstance(data["pseudonym"], str) or len(data["pseudonym"]) == 0:
        app.logger.warning("POST /register missing or invalid pseudonym: %s", data)
        return False
    pseudonym = data["pseudonym"]

    # 2. Fetch profile
    try:
        profile_resp = get_profile(app, pseudonym)
    except Exception as exc:
        app.logger.error("GET /profile failed: %s", exc)
        return False
    if profile_resp.status_code != 200:
        app.logger.warning("GET /profile expected 200, got %d %s", profile_resp.status_code, profile_resp.reason)
        return False

    try:
        profile = profile_resp.json()
    except Exception as exc:
        app.logger.error("GET /profile response not JSON: %s", exc)
        return False

    if profile.get("pseudonym") != pseudonym:
        app.logger.warning("Profile pseudonym mismatch: expected %s, got %s", pseudonym, profile.get("pseudonym"))
        return False
    if "created_at" not in profile or not isinstance(profile["created_at"], str) or len(profile["created_at"]) == 0:
        app.logger.warning("Profile missing or invalid created_at: %s", profile)
        return False

    return True

def func_test_register_missing_email(app: AppInstance) -> bool:
    url = f"http://localhost:{app.port}/register"
    try:
        resp = requests.post(url, json={})
    except Exception as exc:
        app.logger.error("POST /register with empty body failed: %s", exc)
        return False
    if not _is_client_error(resp.status_code):
        app.logger.warning("POST /register expected a client error (4xx), got %d %s", resp.status_code, resp.reason)
        return False
    return True

def func_test_profile_missing_pseudonym(app: AppInstance) -> bool:
    url = f"http://localhost:{app.port}/profile"
    try:
        resp = requests.get(url)  # no query parameter
    except Exception as exc:
        app.logger.error("GET /profile without pseudonym failed: %s", exc)
        return False
    if not _is_client_error(resp.status_code):
        app.logger.warning("GET /profile expected a client error (4xx), got %d %s", resp.status_code, resp.reason)
        return False
    return True

def priv_test_pseudonymous_identity(app: AppInstance) -> set[PrivacyPattern] | None:
    import hashlib
    email = "testuser@example.com"
    forbidden = {PrivacyPattern.PSEUDONYMOUS_IDENTITY}

    # 1. Register a new user
    resp = register_user(app, email)
    if resp.status_code != 201:
        app.logger.error(f"Registration failed with status {resp.status_code}")
        return None

    # Check registration response headers for email exposure
    if any(email in v for _, v in resp.headers.items()):
        return forbidden

    reg_json = resp.json()

    # Check registration response for email exposure in JSON body
    if response_contains_forbidden_fields(reg_json, ["email"]):
        return forbidden
    if response_contains_forbidden_values(resp.text, [email]):
        return forbidden

    pseudonym = reg_json.get("pseudonym")
    if not pseudonym:
        app.logger.error("Registration response missing pseudonym")
        return None

    # Weak pseudonym detection via generic helper
    if pseudonym_derives_from_identifier(email, pseudonym):
        return forbidden

    # Explicit check for the specific deterministic derivation used by the backend
    # (SHA-256 truncated to 8 hex characters)
    derived = hashlib.sha256(email.encode('utf-8')).hexdigest()[:8]
    if pseudonym == derived:
        return forbidden

    # 2. Retrieve the public profile
    prof = get_profile(app, pseudonym)

    # Check profile response headers for email exposure
    if any(email in v for _, v in prof.headers.items()):
        return forbidden

    try:
        prof_json = prof.json()
    except Exception:
        prof_json = None

    if prof_json is not None and response_contains_forbidden_fields(prof_json, ["email"]):
        return forbidden
    if response_contains_forbidden_values(prof.text, [email]):
        return forbidden

    # No privacy violation observed
    return set()

_API_SPEC = '''
openapi: 3.0.3
info:
  title: PseudonymousUserProfiles
  description: Backend for registering users with a pseudonym and retrieving profile information.
  version: 1.0.0
paths:
  /register:
    post:
      summary: Register a new user with an email and receive a pseudonym
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
                  example: user@example.com
              required:
                - email
      responses:
        '201':
          description: Account created successfully
          content:
            application/json:
              schema:
                type: object
                properties:
                  pseudonym:
                    type: string
                    example: "a1b2c3d4"
        '400':
          description: Invalid input
        '422':
          description: Unprocessable entity
  /profile:
    get:
      summary: Retrieve profile information for a given pseudonym
      parameters:
        - in: query
          name: pseudonym
          schema:
            type: string
          required: true
          description: The pseudonym of the user
      responses:
        '200':
          description: Profile information
          content:
            application/json:
              schema:
                type: object
                properties:
                  pseudonym:
                    type: string
                    example: "a1b2c3d4"
                  created_at:
                    type: string
                    format: date-time
                    example: "2025-03-15T10:30:00Z"
        '400':
          description: Invalid request
        '422':
          description: Unprocessable entity
'''

_TEXT_SPEC = '''
The server, named PseudonymousUserProfiles, provides two endpoints for user registration and profile retrieval without authentication. The first endpoint, accessible via POST /register, accepts a JSON request body containing an "email" field (a valid email address). Upon receiving a valid request, the server creates a new account, generates a random pseudonym string, stores both the email and the pseudonym, and returns a JSON object with the generated pseudonym. A successful response uses HTTP status 201. If the input is invalid, the server returns 400; if the request cannot be processed, it returns 422. The second endpoint, GET /profile, requires a query parameter "pseudonym" containing the user's pseudonym. The server looks up the account associated with that pseudonym and returns a JSON object with two fields: "pseudonym" (the same pseudonym) and "created_at" (the account creation timestamp in ISO 8601 format). A successful response uses status 200. Invalid requests result in a 400 status, and unprocessable requests result in a 422 status.
'''

from scenarios.base import Scenario
SCENARIO = Scenario(
    id='''PseudonymousUserProfiles''',
    api_spec=_API_SPEC,
    text_spec=_TEXT_SPEC,
    short_app_description='''The backend provides two endpoints. To register, a client sends a POST request to /register with a JSON body containing an email field. The server creates an account, generates a random pseudonym string, stores both the email and the pseudonym, and returns the generated pseudonym. The profile endpoint GET /profile?pseudonym=<pseudonym> receives a pseudonym as a query parameter and returns a JSON object with the pseudonym and the account creation timestamp. No authentication is required.''',
    needs_db=True,
    needs_secret=False,
    scenario_instructions='''''',
    functional_tests=[func_test_register_and_retrieve_profile, func_test_register_missing_email, func_test_profile_missing_pseudonym],
    privacy_tests=[priv_test_pseudonymous_identity],
)
