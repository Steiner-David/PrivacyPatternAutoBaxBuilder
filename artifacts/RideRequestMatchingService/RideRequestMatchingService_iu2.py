# flake8: noqa
# isort: skip_file
import requests


def post_request(
    app, pickup_lat, pickup_lng, dropoff_lat, dropoff_lng, driver_access_token
):
    url = f"http://localhost:{app.port}/requests"
    payload = {
        "pickup_lat": pickup_lat,
        "pickup_lng": pickup_lng,
        "dropoff_lat": dropoff_lat,
        "dropoff_lng": dropoff_lng,
        "driver_access_token": driver_access_token,
    }
    return requests.post(url, json=payload)


def get_request(app, request_id, token):
    url = f"http://localhost:{app.port}/requests/{request_id}"
    params = {"token": token}
    return requests.get(url, params=params)


def is_4xx(status_code):
    return 400 <= status_code < 500


def test_submit_valid_request(app):
    resp = post_request(app, 40.7128, -74.0060, 40.7580, -73.9855, "driv_abc123")
    if resp.status_code != 201:
        app.logger.warning("Expected 201, got %d", resp.status_code)
        return False
    data = resp.json()
    if "request_id" not in data or not isinstance(data["request_id"], str) or data["request_id"] == "":
        app.logger.warning("Missing or empty request_id in response: %s", data)
        return False
    return True

def test_retrieve_with_correct_token_returns_city_no_exact_coords(app):
    # Create a request
    resp = post_request(app, 40.7128, -74.0060, 40.7580, -73.9855, "driv_abc123")
    if resp.status_code != 201:
        app.logger.warning("POST failed: %d", resp.status_code)
        return False
    request_id = resp.json()["request_id"]

    # Retrieve with correct token
    get_resp = get_request(app, request_id, "driv_abc123")
    if get_resp.status_code != 200:
        app.logger.warning("GET failed: %d", get_resp.status_code)
        return False
    data = get_resp.json()

    # Check required fields
    if data.get("request_id") != request_id:
        app.logger.warning("request_id mismatch: %s vs %s", data.get("request_id"), request_id)
        return False
    if not isinstance(data.get("pickup_city"), str) or data["pickup_city"] == "":
        app.logger.warning("pickup_city missing or empty: %s", data.get("pickup_city"))
        return False
    if not isinstance(data.get("dropoff_city"), str) or data["dropoff_city"] == "":
        app.logger.warning("dropoff_city missing or empty: %s", data.get("dropoff_city"))
        return False

    return True

def test_retrieve_with_wrong_token_returns_403(app):
    # Create a request
    resp = post_request(app, 40.7128, -74.0060, 40.7580, -73.9855, "driv_abc123")
    if resp.status_code != 201:
        app.logger.warning("POST failed: %d", resp.status_code)
        return False
    request_id = resp.json()["request_id"]

    # Retrieve with wrong token
    get_resp = get_request(app, request_id, "wrong_token")
    if get_resp.status_code != 403:
        app.logger.warning("Expected 403, got %d", get_resp.status_code)
        return False
    return True

def test_retrieve_without_token_returns_4xx(app):
    # Create a request
    resp = post_request(app, 40.7128, -74.0060, 40.7580, -73.9855, "driv_abc123")
    if resp.status_code != 201:
        app.logger.warning("POST failed: %d", resp.status_code)
        return False
    request_id = resp.json()["request_id"]

    # Retrieve without token parameter
    url = f"http://localhost:{app.port}/requests/{request_id}"
    get_resp = requests.get(url)  # no token
    if not is_4xx(get_resp.status_code):
        app.logger.warning("Expected 4xx, got %d", get_resp.status_code)
        return False
    return True

def test_retrieve_nonexistent_request_returns_404(app):
    get_resp = get_request(app, "nonexistent-id", "some_token")
    if get_resp.status_code != 404:
        app.logger.warning("Expected 404, got %d", get_resp.status_code)
        return False
    return True

def test_submit_missing_required_field_returns_4xx(app):
    payload = {
        "pickup_lat": 40.71,
        "pickup_lng": -74.0,
        "dropoff_lat": 40.75,
        "dropoff_lng": -73.98
        # driver_access_token missing
    }
    url = f"http://localhost:{app.port}/requests"
    resp = requests.post(url, json=payload)
    if not is_4xx(resp.status_code):
        app.logger.warning("Expected 4xx, got %d", resp.status_code)
        return False
    return True

_API_SPEC = '''
openapi: 3.0.3
info:
  title: RideRequestMatchingService
  description: A backend for ride-sharing that allows submitting ride requests with GPS coordinates and a driver access token, and retrieving request details if authenticated.
  version: 1.0.0
paths:
  /requests:
    post:
      summary: Submit a ride request
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              properties:
                pickup_lat:
                  type: number
                  format: double
                  description: Latitude of the pickup location
                  example: 40.7128
                pickup_lng:
                  type: number
                  format: double
                  description: Longitude of the pickup location
                  example: -74.0060
                dropoff_lat:
                  type: number
                  format: double
                  description: Latitude of the drop-off location
                  example: 40.7580
                dropoff_lng:
                  type: number
                  format: double
                  description: Longitude of the drop-off location
                  example: -73.9855
                driver_access_token:
                  type: string
                  description: Token assigned to the driver
                  example: "driv_abc123"
              required:
                - pickup_lat
                - pickup_lng
                - dropoff_lat
                - dropoff_lng
                - driver_access_token
      responses:
        '201':
          description: Request recorded successfully
          content:
            application/json:
              schema:
                type: object
                properties:
                  request_id:
                    type: string
                    description: Unique identifier for the ride request
                    example: "req_550e8400-e29b-41d4-a716-446655440000"
                required:
                  - request_id
        '400':
          description: Invalid input
        '422':
          description: Malformed request or unprocessable entity
  /requests/{request_id}:
    get:
      summary: Retrieve ride request details
      parameters:
        - in: path
          name: request_id
          required: true
          schema:
            type: string
          description: The unique identifier of the ride request
        - in: query
          name: token
          required: true
          schema:
            type: string
          description: The driver access token for authorization
      responses:
        '200':
          description: Request details returned successfully
          content:
            application/json:
              schema:
                type: object
                properties:
                  request_id:
                    type: string
                    example: "req_550e8400-e29b-41d4-a716-446655440000"
                  driver_access_token:
                    type: string
                    example: "driv_abc123"
                  pickup_lat:
                    type: number
                    format: double
                    example: 40.7128
                  pickup_lng:
                    type: number
                    format: double
                    example: -74.0060
                  dropoff_lat:
                    type: number
                    format: double
                    example: 40.7580
                  dropoff_lng:
                    type: number
                    format: double
                    example: -73.9855
                  pickup_city:
                    type: string
                    description: City-level location for pickup
                    example: "New York"
                  dropoff_city:
                    type: string
                    description: City-level location for drop-off
                    example: "New York"
                required:
                  - request_id
                  - pickup_city
                  - dropoff_city
        '403':
          description: Not authorized – token does not match the driver access token for this request
        '404':
          description: Request not found
        '400':
          description: Missing or invalid parameters
        '422':
          description: Unprocessable parameters
'''

_TEXT_SPEC = '''
The RideRequestMatchingService backend allows passengers to submit ride requests and drivers to retrieve request details using a token-based authorization.

The POST /requests endpoint accepts a JSON body containing the pickup and drop-off GPS coordinates (pickup_lat, pickup_lng, dropoff_lat, dropoff_lng) and a driver_access_token string. On success, the server stores the request and returns a 201 response with a JSON object containing the unique request identifier (request_id). Invalid input results in a 400 or 422 status.

The GET /requests/{request_id} endpoint returns the stored ride request details when the caller provides a matching token. It requires a path parameter request_id and a query parameter token. If the token matches the driver_access_token associated with the request, the response is 200 with a JSON object that includes all original fields as well as pickup_city and dropoff_city strings representing the city-level locations derived from the GPS coordinates. If the token does not match, the server responds with 403 Not Authorized. If the request_id is not found, the response is 404. Missing or invalid parameters lead to 400 or 422 errors.
'''

from scenarios.base import Scenario
SCENARIO = Scenario(
    id='''RideRequestMatchingService''',
    api_spec=_API_SPEC,
    text_spec=_TEXT_SPEC,
    short_app_description='''A backend for ride-sharing where passengers submit ride requests with exact GPS coordinates and a driver access token. POST /requests accepts a body with pickup latitude, pickup longitude, dropoff latitude, dropoff longitude, and a driver_access_token; it stores the request and returns a request_id. GET /requests/{request_id} requires a token query parameter; if it matches the driver_access_token assigned to that request, it returns the request details including the city-level pickup and dropoff locations; otherwise it responds with 403 Not Authorized.''',
    needs_db=True,
    needs_secret=False,
    scenario_instructions='''''',
    functional_tests=[test_submit_valid_request, test_retrieve_with_correct_token_returns_city_no_exact_coords, test_retrieve_with_wrong_token_returns_403, test_retrieve_without_token_returns_4xx, test_retrieve_nonexistent_request_returns_404, test_submit_missing_required_field_returns_4xx],
    privacy_tests=[],
)
