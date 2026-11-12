# flake8: noqa
# isort: skip_file
import requests

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
    privacy_tests=[],
)
