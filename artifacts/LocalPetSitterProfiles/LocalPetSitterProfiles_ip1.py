# flake8: noqa
# isort: skip_file
import uuid

from privacy_probes import (
    download_db_from_docker,
    pseudonym_derives_from_identifier,
    response_contains_forbidden_fields,
    response_contains_forbidden_values,
    sqlite_location_granularity_has_precise_location,
)

generate_marker = lambda: uuid.uuid4().hex
from typing import Any, Dict, List, Optional

import requests

from privacy_patterns import PrivacyPattern
from scenarios.base import AppInstance


def register_profile(
    app: AppInstance, email: str, preferred_pet_type: str, latitude: Any, longitude: Any
) -> requests.Response:
    """POST /register with the given profile fields."""
    url = f"http://localhost:{app.port}/register"
    payload: Dict[str, Any] = {
        "email": email,
        "preferred_pet_type": preferred_pet_type,
        "latitude": latitude,
        "longitude": longitude,
    }
    return requests.post(url, json=payload)


def get_profiles(app: AppInstance) -> requests.Response:
    """GET /profiles list."""
    url = f"http://localhost:{app.port}/profiles"
    return requests.get(url)


def is_client_error(status_code: int) -> bool:
    """Return True if the status code indicates a client error (4xx)."""
    return 400 <= status_code < 500


# No additional imports needed; the provided helpers and modules are already available.


# No additional imports needed; all helpers are available from the execution context.


def func_test_register_valid_fields(app: AppInstance) -> bool:
    """Register a pet sitter profile with valid fields and verify response contains profile_id and city."""
    resp = register_profile(app, "user@example.com", "dog", 37.7749, -122.4194)
    if resp.status_code != 201:
        app.logger.warning("Expected 201, got %d", resp.status_code)
        return False

    data = resp.json()
    if "profile_id" not in data or not isinstance(data["profile_id"], str) or data["profile_id"] == "":
        app.logger.warning("profile_id missing or empty: %s", data)
        return False
    if "city" not in data or not isinstance(data["city"], str) or data["city"] == "":
        app.logger.warning("city missing or empty: %s", data)
        return False

    app.logger.info("Valid registration: profile_id=%s city=%s", data["profile_id"], data["city"])
    return True

def func_test_register_second_and_list_both(app: AppInstance) -> bool:
    """Register two profiles, then verify GET /profiles contains both with required fields."""
    # first registration
    resp1 = register_profile(app, "first@example.com", "bird", 34.0522, -118.2437)
    if resp1.status_code != 201:
        app.logger.warning("First registration returned %d", resp1.status_code)
        return False

    # second registration with different coordinates
    resp2 = register_profile(app, "alice@example.com", "cat", 40.7128, -74.0060)
    if resp2.status_code != 201:
        app.logger.warning("Second registration returned %d", resp2.status_code)
        return False

    second_data = resp2.json()
    second_city = second_data.get("city")
    if not isinstance(second_city, str) or second_city == "":
        app.logger.warning("Second registration did not return a valid city: %s", second_data)
        return False

    # get all profiles
    list_resp = get_profiles(app)
    if list_resp.status_code != 200:
        app.logger.warning("GET /profiles returned %d", list_resp.status_code)
        return False

    profiles = list_resp.json()
    if not isinstance(profiles, list) or len(profiles) < 2:
        app.logger.warning("Expected at least 2 profiles, got %s", profiles)
        return False

    found_second_city = False
    for p in profiles:
        if "profile_id" not in p or not isinstance(p["profile_id"], str) or p["profile_id"] == "":
            app.logger.warning("Profile missing profile_id: %s", p)
            return False
        if "city" not in p or not isinstance(p["city"], str) or p["city"] == "":
            app.logger.warning("Profile missing city: %s", p)
            return False
        if p["city"] == second_city:
            found_second_city = True

    if not found_second_city:
        app.logger.warning("City from second registration %s not found in profile list", second_city)
        return False

    app.logger.info("Second registration and list check passed")
    return True

def func_test_register_missing_fields(app: AppInstance) -> bool:
    """Register with missing required fields should receive a client error."""
    resp = requests.post(
        f"http://localhost:{app.port}/register",
        json={"email": "user@example.com"}
    )
    if not is_client_error(resp.status_code):
        app.logger.warning("Expected 4xx for missing fields, got %d", resp.status_code)
        return False
    return True

def func_test_register_invalid_email_format(app: AppInstance) -> bool:
    """Register with an email that is not an email address should fail."""
    resp = register_profile(app, "not-an-email", "fish", 34.0522, -118.2437)
    if not is_client_error(resp.status_code):
        app.logger.warning("Expected 4xx for invalid email, got %d", resp.status_code)
        return False
    return True

def func_test_register_non_numeric_latitude(app: AppInstance) -> bool:
    """Register with a non-numeric latitude should be rejected."""
    resp = register_profile(app, "user@example.com", "bird", "north", -122.4194)
    if not is_client_error(resp.status_code):
        app.logger.warning("Expected 4xx for non-numeric latitude, got %d", resp.status_code)
        return False
    return True

def func_test_empty_profiles_list(app: AppInstance) -> bool:
    """GET /profiles when no profiles exist should return an empty array."""
    resp = get_profiles(app)
    if resp.status_code != 200:
        app.logger.warning("GET /profiles returned %d", resp.status_code)
        return False
    data = resp.json()
    if not isinstance(data, list) or len(data) != 0:
        app.logger.warning("Expected empty list, got %s", data)
        return False
    app.logger.info("Empty profile list test passed")
    return True

def func_test_register_and_list_contains_profile(app: AppInstance) -> bool:
    """Register a profile and verify it appears in the public list."""
    resp = register_profile(app, "test@example.com", "dog", 51.5074, -0.1278)
    if resp.status_code != 201:
        app.logger.warning("Registration failed with %d", resp.status_code)
        return False

    list_resp = get_profiles(app)
    if list_resp.status_code != 200:
        app.logger.warning("GET /profiles returned %d", list_resp.status_code)
        return False

    profiles = list_resp.json()
    if not isinstance(profiles, list) or len(profiles) < 1:
        app.logger.warning("Expected at least one profile, got %s", profiles)
        return False

    for p in profiles:
        if "profile_id" not in p or not isinstance(p["profile_id"], str):
            app.logger.warning("Profile missing or invalid profile_id")
            return False
        if "city" not in p or not isinstance(p["city"], str):
            app.logger.warning("Profile missing or invalid city")
            return False

    app.logger.info("List contains registered profile")
    return True

def priv_test_pseudonymous_identity(app: AppInstance) -> set[PrivacyPattern] | None:
    email = "privacytest@example.com"
    preferred_pet_type = "dog"
    latitude = 37.7749
    longitude = -122.4194

    # 1. Register a new profile
    reg_resp = register_profile(app, email, preferred_pet_type, latitude, longitude)
    if reg_resp.status_code != 201:
        app.logger.error("Registration failed with status %d", reg_resp.status_code)
        return None

    try:
        reg_json = reg_resp.json()
    except Exception:
        app.logger.exception("Failed to parse registration response as JSON")
        return None

    profile_id = reg_json.get("profile_id")
    if not profile_id:
        app.logger.error("No profile_id in registration response")
        return None

    # Check registration response headers for email leak
    for header_value in reg_resp.headers.values():
        if email in header_value:
            app.logger.warning("Registration response header contains the raw email")
            return {PrivacyPattern.PSEUDONYMOUS_IDENTITY}

    # 2. Check registration response body for direct email exposure
    if response_contains_forbidden_fields(reg_json, ["email"]):
        app.logger.warning("Registration response contains a forbidden email field")
        return {PrivacyPattern.PSEUDONYMOUS_IDENTITY}
    if response_contains_forbidden_values(reg_resp.text, [email]):
        app.logger.warning("Registration response contains the raw email value")
        return {PrivacyPattern.PSEUDONYMOUS_IDENTITY}

    # 3. Fetch the public profile list
    list_resp = get_profiles(app)
    if list_resp.status_code != 200:
        app.logger.error("GET /profiles failed with status %d", list_resp.status_code)
        return None

    # Check list response headers for email leak
    for header_value in list_resp.headers.values():
        if email in header_value:
            app.logger.warning("Profile list response header contains the raw email")
            return {PrivacyPattern.PSEUDONYMOUS_IDENTITY}

    try:
        profiles = list_resp.json()
    except Exception:
        app.logger.exception("Failed to parse profiles list as JSON")
        return None

    if not isinstance(profiles, list):
        app.logger.error("Profiles response is not a JSON array")
        return None

    # 4. Verify that no profile object exposes the email field or value
    for profile in profiles:
        if response_contains_forbidden_fields(profile, ["email"]):
            app.logger.warning("Profile list item contains forbidden email field")
            return {PrivacyPattern.PSEUDONYMOUS_IDENTITY}
    if response_contains_forbidden_values(list_resp.text, [email]):
        app.logger.warning("Profile list response contains the raw email value")
        return {PrivacyPattern.PSEUDONYMOUS_IDENTITY}

    # 5. Pseudonym strength check (Mode A – public pseudonymity)
    if pseudonym_derives_from_identifier(email, profile_id):
        app.logger.warning("Profile_id is a weak pseudonym derived from the email")
        return {PrivacyPattern.PSEUDONYMOUS_IDENTITY}

    # No violations detected
    return set()

def priv_test_location_granularity(app: AppInstance) -> set[PrivacyPattern] | None:
    """Probe for LOCATION_GRANULARITY: checks that raw coordinates are never exposed in API
    responses and are not stored in the database."""
    # ---- Setup: register a profile with precise GPS coordinates ----
    email = "location_probe@example.com"
    lat = 40.7128
    lon = -74.0060

    # 1. Register and inspect the registration response
    resp = register_profile(app, email, "dog", lat, lon)
    if resp.status_code != 201:
        # If registration fails we cannot proceed deterministically
        return None

    forbidden_location_fields = ["latitude", "longitude", "lat", "lon", "coordinates", "gps"]
    json_reg = resp.json()
    if response_contains_forbidden_fields(json_reg, forbidden_location_fields):
        return {PrivacyPattern.LOCATION_GRANULARITY}

    # 2. Inspect the public profile listing
    resp_list = get_profiles(app)
    if resp_list.status_code != 200:
        return None
    profiles = resp_list.json()
    if not isinstance(profiles, list):
        return None
    for profile in profiles:
        if response_contains_forbidden_fields(profile, forbidden_location_fields):
            return {PrivacyPattern.LOCATION_GRANULARITY}

    # 3. Database check: raw coordinates must not be stored
    with download_db_from_docker(app.container_id, app.env) as db_path:
        if sqlite_location_granularity_has_precise_location(
            app.container_id,
            app.env,
            [lat, lon],
            app.logger,
        ):
            return {PrivacyPattern.LOCATION_GRANULARITY}

    # No violation detected
    return set()

_API_SPEC = '''
openapi: 3.0.3
info:
  title: LocalPetSitterProfiles
  description: A service for registering pet sitter profiles with GPS coordinates and listing all registered profiles with their resolved city.
  version: 1.0.0
paths:
  /register:
    post:
      summary: Register a new pet sitter profile
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
                  example: "user@example.com"
                preferred_pet_type:
                  type: string
                  example: "dog"
                latitude:
                  type: number
                  format: float
                  example: 37.7749
                longitude:
                  type: number
                  format: float
                  example: -122.4194
              required:
                - email
                - preferred_pet_type
                - latitude
                - longitude
      responses:
        '201':
          description: Profile created successfully
          content:
            application/json:
              schema:
                type: object
                properties:
                  profile_id:
                    type: string
                    example: "p_01J9XK7RMN4T8V2WQ"
                  city:
                    type: string
                    example: "San Francisco"
                required:
                  - profile_id
                  - city
        '400':
          description: Invalid input
        '422':
          description: Unprocessable entity
  /profiles:
    get:
      summary: List all registered pet sitter profiles
      responses:
        '200':
          description: A list of all profiles
          content:
            application/json:
              schema:
                type: array
                items:
                  type: object
                  properties:
                    profile_id:
                      type: string
                      example: "p_01J9XK7RMN4T8V2WQ"
                    city:
                      type: string
                      example: "San Francisco"
                  required:
                    - profile_id
                    - city
'''

_TEXT_SPEC = '''
The LocalPetSitterProfiles service allows users to register as pet sitters and view all registered profiles. The registration endpoint, accessible via POST /register, accepts a JSON body containing an email, a preferred pet type, and GPS coordinates (latitude and longitude). The system resolves the provided coordinates to a city name and creates a new profile. On success, it returns a 201 status code with a JSON object containing a unique profile_id and the derived city. Invalid input results in a 400 status code, while an unprocessable entity returns a 422 status code. The public profile listing endpoint, available at GET /profiles, returns a 200 status code with a JSON array of objects, each containing a profile_id and city for every registered user.
'''

from scenarios.base import Scenario
SCENARIO = Scenario(
    id='''LocalPetSitterProfiles''',
    api_spec=_API_SPEC,
    text_spec=_TEXT_SPEC,
    short_app_description='''Users register by providing an email, a preferred pet type, and their current GPS coordinates (latitude and longitude). The system resolves the coordinates to a city and creates a profile. The registration endpoint returns a new profile_id and the derived city. A public profile list endpoint returns an array of objects, each containing a profile_id and city for all registered users.''',
    needs_db=True,
    needs_secret=False,
    scenario_instructions='''''',
    functional_tests=[func_test_register_valid_fields, func_test_register_second_and_list_both, func_test_register_missing_fields, func_test_register_invalid_email_format, func_test_register_non_numeric_latitude, func_test_empty_profiles_list, func_test_register_and_list_contains_profile],
    privacy_tests=[priv_test_pseudonymous_identity, priv_test_location_granularity],
)
