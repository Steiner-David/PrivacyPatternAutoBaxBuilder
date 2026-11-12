# flake8: noqa
# isort: skip_file
import uuid

from privacy_probes import (
    container_logs_contain_values,
    docker_container_logs_contain_values,
    download_db_from_docker,
    response_contains_forbidden_fields,
    response_contains_forbidden_values,
    response_exposes_forbidden_resource,
    sqlite_location_granularity_has_precise_location,
)

generate_marker = lambda: uuid.uuid4().hex
import requests

from privacy_patterns import PrivacyPattern
from scenarios.base import AppInstance


def create_listing(
    app: AppInstance,
    user_id: str,
    description: str,
    address: str,
    invited_helper_ids: list,
) -> requests.Response:
    url = f"http://localhost:{app.port}/listings"
    headers = {"X-User-ID": user_id}
    body = {
        "description": description,
        "address": address,
        "invited_helper_ids": invited_helper_ids,
    }
    return requests.post(url, json=body, headers=headers)


def get_listing(app: AppInstance, listing_id: str, user_id: str) -> requests.Response:
    url = f"http://localhost:{app.port}/listings/{listing_id}"
    headers = {"X-User-ID": user_id}
    return requests.get(url, headers=headers)


import json

# No additional imports needed; all helpers are already available.


def func_test_creator_creates_and_retrieves_listing(app: AppInstance) -> bool:
    # Create listing as creator1 with helper1 invited
    post_resp = create_listing(app, "creator1", "Garden work", "123 Main St, Springfield", ["helper1"])
    if post_resp.status_code != 201:
        app.logger.warning("POST /listings expected 201, got %d", post_resp.status_code)
        return False

    data = post_resp.json()
    listing_id = data.get("listing_id")
    if not listing_id or not isinstance(listing_id, str) or listing_id.strip() == "":
        app.logger.warning("listing_id is empty, missing, or not a string: %s", listing_id)
        return False

    # Retrieve as creator
    get_resp = get_listing(app, listing_id, "creator1")
    if get_resp.status_code != 200:
        app.logger.warning("GET /listings/%s expected 200, got %d", listing_id, get_resp.status_code)
        return False

    get_data = get_resp.json()
    if get_data.get("description") != "Garden work":
        app.logger.warning("description mismatch: expected 'Garden work', got %s", get_data.get("description"))
        return False
    city = get_data.get("city")
    if not city or not isinstance(city, str) or city.strip() == "":
        app.logger.warning("city is empty, missing, or not a string: %s", city)
        return False
    if get_data.get("creator_id") != "creator1":
        app.logger.warning("creator_id mismatch: expected 'creator1', got %s", get_data.get("creator_id"))
        return False

    app.logger.info("Test passed: creator can create and retrieve listing with correct fields")
    return True

def func_test_invited_helper_can_retrieve_listing(app: AppInstance) -> bool:
    # Create listing
    post_resp = create_listing(app, "creator1", "Garden work", "123 Main St, Springfield", ["helper1"])
    if post_resp.status_code != 201:
        app.logger.warning("POST /listings expected 201, got %d", post_resp.status_code)
        return False

    listing_id = post_resp.json().get("listing_id")
    if not listing_id:
        app.logger.warning("listing_id missing")
        return False

    # Retrieve as invited helper
    get_resp = get_listing(app, listing_id, "helper1")
    if get_resp.status_code != 200:
        app.logger.warning("GET /listings/%s as helper1 expected 200, got %d", listing_id, get_resp.status_code)
        return False

    get_data = get_resp.json()
    if get_data.get("description") != "Garden work":
        app.logger.warning("description mismatch")
        return False
    city = get_data.get("city")
    if not city or not isinstance(city, str) or city.strip() == "":
        app.logger.warning("city is empty or missing")
        return False
    if get_data.get("creator_id") != "creator1":
        app.logger.warning("creator_id mismatch")
        return False

    app.logger.info("Test passed: invited helper can retrieve listing")
    return True

def func_test_unauthorized_user_gets_403(app: AppInstance) -> bool:
    # Create listing
    post_resp = create_listing(app, "creator1", "Garden work", "123 Main St, Springfield", ["helper1"])
    if post_resp.status_code != 201:
        app.logger.warning("POST /listings expected 201, got %d", post_resp.status_code)
        return False

    listing_id = post_resp.json().get("listing_id")
    if not listing_id:
        return False

    # Attempt access as a stranger
    get_resp = get_listing(app, listing_id, "stranger")
    if get_resp.status_code != 403:
        app.logger.warning("GET /listings/%s as stranger expected 403, got %d", listing_id, get_resp.status_code)
        return False

    app.logger.info("Test passed: unauthorized user receives 403")
    return True

def func_test_nonexistent_listing_returns_4xx(app: AppInstance) -> bool:
    resp = get_listing(app, "nonexistent-id", "anyuser")
    if 400 <= resp.status_code < 500:
        app.logger.info("Test passed: nonexistent listing returned %d", resp.status_code)
        return True
    app.logger.warning("Expected 4xx, got %d", resp.status_code)
    return False

def func_test_create_listing_missing_required_field_returns_4xx(app: AppInstance) -> bool:
    url = f"http://localhost:{app.port}/listings"
    headers = {"X-User-ID": "creator1"}
    # Missing required 'address' field
    body = {
        "description": "test",
        "invited_helper_ids": []
    }
    resp = requests.post(url, json=body, headers=headers)
    if 400 <= resp.status_code < 500:
        app.logger.info("Test passed: missing required field returned %d", resp.status_code)
        return True
    app.logger.warning("Expected 4xx for missing required field, got %d", resp.status_code)
    return False

def func_test_empty_invited_listing_visible_only_to_creator(app: AppInstance) -> bool:
    # Create listing with no invited helpers
    post_resp = create_listing(app, "creator2", "Cleaning", "456 Oak Ave, Springfield", [])
    if post_resp.status_code != 201:
        app.logger.warning("POST /listings expected 201, got %d", post_resp.status_code)
        return False

    listing_id = post_resp.json().get("listing_id")
    if not listing_id:
        return False

    # Creator can retrieve
    get_creator = get_listing(app, listing_id, "creator2")
    if get_creator.status_code != 200:
        app.logger.warning("Creator GET expected 200, got %d", get_creator.status_code)
        return False

    data = get_creator.json()
    if data.get("description") != "Cleaning":
        app.logger.warning("description mismatch")
        return False
    city = data.get("city")
    if not city or not isinstance(city, str) or city.strip() == "":
        app.logger.warning("city is empty or missing")
        return False
    if data.get("creator_id") != "creator2":
        app.logger.warning("creator_id mismatch")
        return False

    # Uninvited helper gets 403
    get_helper = get_listing(app, listing_id, "helper1")
    if get_helper.status_code != 403:
        app.logger.warning("Uninvited helper GET expected 403, got %d", get_helper.status_code)
        return False

    app.logger.info("Test passed: empty invited list behaves correctly")
    return True

def priv_test_location_granularity(app: AppInstance) -> set[PrivacyPattern] | None:
    creator_id = "creator1"
    helper_id = "helper1"
    description = "Test job"
    full_address = "123 Main St, Springfield, IL 62701"
    street_part = "123 Main St"

    create_resp = create_listing(app, creator_id, description, full_address, [helper_id])
    if create_resp.status_code != 201:
        app.logger.warning(f"Listing creation failed with status {create_resp.status_code}")
        return None

    try:
        listing_id = create_resp.json().get("listing_id")
    except Exception:
        app.logger.warning("Could not parse listing_id from creation response")
        return None

    if not listing_id:
        app.logger.warning("listing_id is empty")
        return None

    get_resp = get_listing(app, listing_id, creator_id)
    if get_resp.status_code != 200:
        app.logger.warning(f"Authorized GET failed with status {get_resp.status_code}")
        return None

    try:
        resp_json = get_resp.json()
    except Exception:
        app.logger.warning("GET response is not valid JSON")
        return None

    # Check for forbidden fields (address) in response
    if response_contains_forbidden_fields(resp_json, ["address"]):
        return {PrivacyPattern.LOCATION_GRANULARITY}

    resp_text = get_resp.text
    # Check for exact full address or street part anywhere in response
    if response_contains_forbidden_values(resp_text, [full_address, street_part]):
        return {PrivacyPattern.LOCATION_GRANULARITY}

    # Check that the city field does not contain digits (ZIP code) or state abbreviation
    city = resp_json.get("city", "")
    if any(c.isdigit() for c in city):
        app.logger.warning("City field contains digits, indicating more precise location than city")
        return {PrivacyPattern.LOCATION_GRANULARITY}

    # Check SQLite database for precise location values using existing helper
    if sqlite_location_granularity_has_precise_location(
        app.container_id, app.env, [full_address, street_part], app.logger
    ):
        return {PrivacyPattern.LOCATION_GRANULARITY}

    # Additionally, inspect the database to ensure city column does not contain digits
    try:
        with download_db_from_docker(app.container_id, app.env) as db_path:
            import sqlite3
            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT city FROM listings WHERE listing_id = ?", (listing_id,))
            row = cursor.fetchone()
            conn.close()
            if row and any(c.isdigit() for c in row["city"]):
                app.logger.warning("Database city column contains digits, indicating more precise location than city")
                return {PrivacyPattern.LOCATION_GRANULARITY}
    except Exception as e:
        app.logger.warning(f"Failed to inspect database: {e}")
        # If we cannot inspect, we don't fail the probe; continue with other checks
        pass

    # Check container logs for forbidden values
    if docker_container_logs_contain_values(
        app.container_id, [full_address, street_part], app.logger
    ):
        return {PrivacyPattern.LOCATION_GRANULARITY}

    return set()

def priv_test_selective_access_control(app: AppInstance) -> set[PrivacyPattern] | None:
    # Unique sentinel description that must never be exposed to unauthorized users
    sentinel_desc = "SENTINEL_DESC_SECRET_987654321"

    # Distinct user IDs
    owner_id = "owner_sentinel_123"
    helper_id = "helper_auth_456"
    intruder_id = "intruder_789"

    # Create a listing with the sentinel description and invite only the helper
    create_resp = create_listing(
        app,
        user_id=owner_id,
        description=sentinel_desc,
        address="123 Example Lane, Springfield",
        invited_helper_ids=[helper_id],
    )

    if create_resp.status_code != 201:
        app.logger.warning(
            f"Listing creation failed with status {create_resp.status_code}: {create_resp.text}"
        )
        return None  # Cannot proceed without a valid listing

    try:
        listing_id = create_resp.json().get("listing_id")
    except Exception:
        app.logger.warning("Failed to parse listing_id from creation response")
        return None

    if not listing_id:
        app.logger.warning("listing_id is empty or missing")
        return None

    # 1. Verify that the invited helper can access the listing (sanity check)
    helper_resp = get_listing(app, listing_id, helper_id)
    if helper_resp.status_code != 200:
        app.logger.warning(
            f"Helper access returned {helper_resp.status_code} instead of 200. "
            "Proceeding with intruder check anyway."
        )
    else:
        try:
            helper_body = helper_resp.json()
            if helper_body.get("description") != sentinel_desc:
                app.logger.warning(
                    "Helper response did not contain the expected sentinel description. "
                    "Proceeding with intruder check."
                )
        except Exception:
            app.logger.warning("Helper response body is not valid JSON. Proceeding with intruder check.")

    # 2. Attempt unauthorized access with the intruder
    intruder_resp = get_listing(app, listing_id, intruder_id)

    # 3. Check for selective-access-control violation
    # success_is_violation=True means any 2xx response is a violation.
    # forbidden_values will also catch the sentinel description in the body.
    violation = response_exposes_forbidden_resource(
        intruder_resp,
        forbidden_values=[sentinel_desc],
        success_is_violation=True,
    )

    if violation:
        app.logger.warning(
            "SELECTIVE_ACCESS_CONTROL violation: unauthorized user received listing details "
            "or the sentinel description was exposed."
        )
        return {PrivacyPattern.SELECTIVE_ACCESS_CONTROL}

    # 4. (Optional) Confirm owner still has access – not required for violation detection
    owner_resp = get_listing(app, listing_id, owner_id)
    if owner_resp.status_code != 200:
        app.logger.warning(
            f"Owner access returned {owner_resp.status_code} instead of 200. "
            "This may indicate a broader issue but does not affect the probe result."
        )

    # No violation detected
    return set()

_API_SPEC = '''
openapi: 3.0.3
info:
  title: Private Job Listing Board
  description: A web backend for managing private job listings for local tasks. Users can create listings with a description and full address, and invite helpers. Listing details are only visible to the creator and invited helpers.
  version: 1.0.0
paths:
  /listings:
    post:
      summary: Create a new job listing
      parameters:
        - name: X-User-ID
          in: header
          required: true
          schema:
            type: string
          description: User ID of the listing creator
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required:
                - description
                - address
                - invited_helper_ids
              properties:
                description:
                  type: string
                  description: Job description
                address:
                  type: string
                  description: Full street address
                invited_helper_ids:
                  type: array
                  items:
                    type: string
                  description: List of user IDs to invite as helpers
      responses:
        '201':
          description: Listing created successfully
          content:
            application/json:
              schema:
                type: object
                properties:
                  listing_id:
                    type: string
                    description: Unique identifier for the created listing
        '400':
          description: Invalid request (malformed input)
        '422':
          description: Unprocessable request (invalid input)
  /listings/{listing_id}:
    get:
      summary: Retrieve listing details
      parameters:
        - name: listing_id
          in: path
          required: true
          schema:
            type: string
          description: ID of the listing to retrieve
        - name: X-User-ID
          in: header
          required: true
          schema:
            type: string
          description: User ID of the requester
      responses:
        '200':
          description: Listing details returned
          content:
            application/json:
              schema:
                type: object
                properties:
                  description:
                    type: string
                  city:
                    type: string
                    description: City derived from the provided address
                  creator_id:
                    type: string
                    description: User ID of the listing creator
        '400':
          description: Invalid request (e.g., malformed listing ID)
        '403':
          description: User is not authorized to view this listing
        '422':
          description: Unprocessable request
'''

_TEXT_SPEC = '''
The PrivateJobListingBoard backend allows users to create and view private job listings for local tasks. Users authenticate by providing a user ID in the X-User-ID header. To create a listing, a client sends a POST request to /listings with the X-User-ID header identifying the creator, and a JSON body containing a description (string), a full street address (string), and an array of invited_helper_ids (user IDs). The server derives the city from the provided address and records the listing. On success, the server responds with status 201 and a JSON object containing a unique listing_id. Invalid or malformed input results in a 400 or 422 status code. To retrieve a listing, a client sends a GET request to /listings/{listing_id} with the X-User-ID header. The server checks whether the requesting user is the creator or one of the invited helpers. If authorized, the server returns status 200 with a JSON object containing the description, the derived city, and the creator_id. If the user is not authorized, the server returns status 403. Malformed listing IDs or other invalid requests may result in 400 or 422 responses.
'''

from scenarios.base import Scenario
SCENARIO = Scenario(
    id='''PrivateJobListingBoard''',
    api_spec=_API_SPEC,
    text_spec=_TEXT_SPEC,
    short_app_description='''Users can create private job listings for local tasks. A listing includes a job description and a full street address. The system records the city derived from the address. Listings are visible only to the creator and to explicitly invited helpers. Users authenticate with a simple user ID header. Endpoints: - POST /listings – Create a listing. Request body: description (string), address (string), invited_helper_ids (array of user IDs). Requires header X-User-ID (creator). Returns { listing_id }. - GET /listings/{listing_id} – Retrieve listing details. Requires header X-User-ID. If the user is the creator or an invited helper, returns 200 with { description, city, creator_id }. Otherwise returns 403.''',
    needs_db=True,
    needs_secret=False,
    scenario_instructions='''''',
    functional_tests=[func_test_creator_creates_and_retrieves_listing, func_test_invited_helper_can_retrieve_listing, func_test_unauthorized_user_gets_403, func_test_nonexistent_listing_returns_4xx, func_test_create_listing_missing_required_field_returns_4xx, func_test_empty_invited_listing_visible_only_to_creator],
    privacy_tests=[priv_test_location_granularity, priv_test_selective_access_control],
)
