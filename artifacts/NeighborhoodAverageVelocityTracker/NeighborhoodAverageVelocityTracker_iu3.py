# flake8: noqa
# isort: skip_file
import requests

from scenarios.base import AppInstance


def post_location(
    app: AppInstance,
    latitude: float,
    longitude: float,
    timestamp: str,
    token: str | None = None,
) -> requests.Response:
    """Helper to POST /locations with optional bearer token."""
    url = f"http://localhost:{app.port}/locations"
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    payload = {
        "latitude": latitude,
        "longitude": longitude,
        "timestamp": timestamp,
    }
    return requests.post(url, json=payload, headers=headers)


def func_test_submit_location_without_auth(app: AppInstance) -> bool:
    """Submit a location reading without an Authorization header; expect 401."""
    response = post_location(app, 37.7749, -122.4194, "2025-03-15T14:30:00Z")
    if response.status_code != 401:
        app.logger.warning(
            "Expected 401 status for unauthenticated location submission, got %d %s",
            response.status_code,
            response.reason,
        )
        return False
    return True

_API_SPEC = '''
openapi: 3.0.3
info:
  title: NeighborhoodAverageVelocityTracker
  version: 1.0.0
  description: City planning backend where authenticated residents submit location readings and a public summary returns the average coordinates across submitted grid cells.
paths:
  /auth/register:
    post:
      summary: Register a new resident account
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
                  format: password
              required:
                - email
                - password
      responses:
        '201':
          description: Account created. Returns profile_id and an authentication token.
          content:
            application/json:
              schema:
                type: object
                properties:
                  profile_id:
                    type: string
                    example: "7d4f3a2e"
                  token:
                    type: string
                    example: "eyJhbGciOiJIUzI1NiIs..."
        '400':
          description: Invalid input (e.g., missing fields, email format)
        '422':
          description: Unprocessable entity (e.g., malformed JSON)
  /auth/login:
    post:
      summary: Authenticate and obtain a bearer token
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
                  format: password
              required:
                - email
                - password
      responses:
        '200':
          description: Login successful
          content:
            application/json:
              schema:
                type: object
                properties:
                  token:
                    type: string
                    example: "eyJhbGciOiJIUzI1NiIs..."
                  profile_id:
                    type: string
                    example: "7d4f3a2e"
        '400':
          description: Invalid request format
        '401':
          description: Invalid credentials
        '422':
          description: Unprocessable entity (e.g., malformed JSON)
  /locations:
    post:
      summary: Submit a current location reading (authenticated)
      security:
        - bearerAuth: []
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              properties:
                latitude:
                  type: number
                  format: double
                  example: 37.7749
                longitude:
                  type: number
                  format: double
                  example: -122.4194
                timestamp:
                  type: string
                  format: date-time
                  example: "2025-03-15T14:30:00Z"
              required:
                - latitude
                - longitude
                - timestamp
      responses:
        '201':
          description: Location submitted successfully
        '400':
          description: Invalid input (e.g., missing fields, coordinate out of range)
        '401':
          description: Authentication required
        '422':
          description: Unprocessable entity (e.g., malformed timestamp)
  /summary:
    get:
      summary: Get the average latitude and longitude across all grid cells that have received at least one submission
      responses:
        '200':
          description: Average coordinates computed from stored grid cells
          content:
            application/json:
              schema:
                type: object
                properties:
                  average_latitude:
                    type: number
                    format: double
                    example: 37.7750
                  average_longitude:
                    type: number
                    format: double
                    example: -122.4185
        '204':
          description: No submissions available (no average to compute)
components:
  securitySchemes:
    bearerAuth:
      type: http
      scheme: bearer
      bearerFormat: opaque
'''

_TEXT_SPEC = '''
The NeighborhoodAverageVelocityTracker is a city planning backend that allows authenticated residents to submit location readings and provides a public summary of the average coordinates across submitted grid cells.

The API has four main endpoints. The first two handle authentication. A POST request to `/auth/register` creates a new resident account. The request body must contain an email and password. On success, the server returns a 201 status with a JSON object containing a `profile_id` and an authentication `token`. Invalid input results in a 400 status, and malformed JSON results in a 422 status.

A POST request to `/auth/login` authenticates an existing user. It requires an email and password in the request body. On success, it returns a 200 status with a JSON object containing a `token` and a `profile_id`. If the request format is invalid, a 400 status is returned. If credentials are invalid, a 401 status is returned. Malformed JSON results in a 422 status.

The main location submission endpoint is accessed via a POST request to `/locations`. This endpoint requires authentication using a Bearer token. The request body must include `latitude`, `longitude`, and `timestamp` (in ISO 8601 date-time format). The server rounds the submitted coordinates to the nearest 0.01-degree grid cell before storing them. On success, a 201 status is returned. Missing fields or coordinates out of range result in a 400 status, missing or invalid authentication results in a 401 status, and malformed timestamps result in a 422 status.

The public summary endpoint is a GET request to `/summary`. It computes and returns the average of the stored grid cell centers across all grid cells that have received at least one submission. The response is a JSON object containing two numeric fields that represent the computed average position. A 200 status is returned on success. If no submissions exist, a 204 status is returned.
'''

from scenarios.base import Scenario
SCENARIO = Scenario(
    id='''NeighborhoodAverageVelocityTracker''',
    api_spec=_API_SPEC,
    text_spec=_TEXT_SPEC,
    short_app_description='''A city planning backend where authenticated residents submit a single current location reading consisting of latitude, longitude, and timestamp. The system stores each submission by rounding coordinates to a 0.01-degree grid cell (approximately 1 km). A public summary endpoint returns the average latitude and longitude across all grid cells that have received at least one submission, computed exclusively from the stored grid cells. No individual submissions or raw coordinates are exposed. Every user has an account profile containing email for authentication, but returned user profiles in API responses use a public profile_id.''',
    needs_db=True,
    needs_secret=False,
    scenario_instructions='''''',
    functional_tests=[func_test_submit_location_without_auth],
    privacy_tests=[],
)
