# flake8: noqa
# isort: skip_file
from typing import Any, Dict, List, Optional

import requests

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
        if "profile_id" not in p or not isinstance(p["profile_id"], str) or p["profile_id"] == "":
            app.logger.warning("Profile missing profile_id")
            return False
        if "city" not in p or not isinstance(p["city"], str) or p["city"] == "":
            app.logger.warning("Profile missing city")
            return False

    app.logger.info("List contains registered profile")
    return True

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
    privacy_tests=[],
)
