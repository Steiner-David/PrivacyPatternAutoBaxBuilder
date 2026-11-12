# flake8: noqa
# isort: skip_file
import uuid

from privacy_probes import (
    container_logs_contain_values,
    docker_container_logs_contain_values,
    response_contains_forbidden_fields,
    response_contains_forbidden_values,
    sqlite_aggregation_gateway_has_raw_records,
    sqlite_location_granularity_has_precise_location,
)

generate_marker = lambda: uuid.uuid4().hex
import requests

from privacy_patterns import PrivacyPattern
from scenarios.base import AppInstance


def post_rating(app: AppInstance, rating, latitude, longitude):
    url = f"http://localhost:{app.port}/ratings"
    payload = {"rating": rating, "latitude": latitude, "longitude": longitude}
    return requests.post(url, json=payload)


def get_stats(app: AppInstance, city: str):
    url = f"http://localhost:{app.port}/stats"
    params = {"city": city}
    return requests.get(url, params=params)


# No additional imports needed; all helpers are provided in the execution context.


# No additional imports needed; all helpers are provided in the execution context.


def func_test_unknown_city_empty(app: AppInstance) -> bool:
    r = get_stats(app, "UnknownCity")
    if r.status_code != 200:
        app.logger.warning("UnknownCity not 200: %d %s", r.status_code, r.reason)
        return False

    data = r.json()
    if data.get("city") != "UnknownCity":
        app.logger.warning("city mismatch: %s", data)
        return False
    if data.get("total") != 0:
        app.logger.warning("total not 0: %s", data.get("total"))
        return False

    avg = data.get("average")
    # average may be 0, 0.0, or None (JSON null)
    if avg is not None:
        try:
            if float(avg) != 0.0:
                app.logger.warning("average not 0 or null: %s", avg)
                return False
        except (ValueError, TypeError):
            app.logger.warning("average invalid: %s", avg)
            return False
    return True

def func_test_missing_fields(app: AppInstance) -> bool:
    url = f"http://localhost:{app.port}/ratings"
    r = requests.post(url, json={"rating": 3.5})
    if not (400 <= r.status_code < 500):
        app.logger.warning("Missing fields not 4xx: %d", r.status_code)
        return False
    return True

def func_test_non_numeric_rating(app: AppInstance) -> bool:
    r = post_rating(app, "good", 40.0, -74.0)
    if not (400 <= r.status_code < 500):
        app.logger.warning("Non-numeric rating not 4xx: %d", r.status_code)
        return False
    return True

def func_test_invalid_latitude(app: AppInstance) -> bool:
    r = post_rating(app, 4.0, 100.0, -74.0)
    if not (400 <= r.status_code < 500):
        app.logger.warning("Invalid latitude not 4xx: %d", r.status_code)
        return False
    return True

def func_test_missing_city_param(app: AppInstance) -> bool:
    url = f"http://localhost:{app.port}/stats"
    r = requests.get(url)
    if not (400 <= r.status_code < 500):
        app.logger.warning("Missing city param not 4xx: %d", r.status_code)
        return False
    return True

def priv_test_location_granularity(app: AppInstance) -> set[PrivacyPattern] | None:
    try:
        # High‑precision coordinates that must not be stored or exposed
        precise_values = [40.7128, -74.0060, 34.0522, -118.2437]

        # Submit two ratings with precise coordinates
        resp1 = post_rating(app, 4.5, 40.7128, -74.0060)
        resp2 = post_rating(app, 3.8, 34.0522, -118.2437)
        if resp1.status_code != 201 or resp2.status_code != 201:
            app.logger.warning("Rating submission failed, cannot complete probe")
            return None

        # 1. Check API response for exact coordinates
        stats_resp = get_stats(app, "New York")  # city name is irrelevant for this check
        if response_contains_forbidden_values(stats_resp.text, precise_values):
            app.logger.info("Exact coordinates found in /stats response")
            return {PrivacyPattern.LOCATION_GRANULARITY}

        # 2. Check SQLite database for stored precise coordinates
        if sqlite_location_granularity_has_precise_location(
            app.container_id, app.env, precise_values, app.logger
        ):
            app.logger.info("Precise coordinates found in SQLite database")
            return {PrivacyPattern.LOCATION_GRANULARITY}

        # 3. Check backend container logs for precise coordinates
        if docker_container_logs_contain_values(app.container_id, precise_values, app.logger):
            app.logger.info("Precise coordinates found in container logs")
            return {PrivacyPattern.LOCATION_GRANULARITY}

        # No violation detected
        return set()
    except Exception as e:
        app.logger.error(f"Location Granularity probe failed: {e}")
        return None

def priv_test_aggregation_gateway(app: AppInstance) -> set[PrivacyPattern] | None:
    # Use the get_stats helper and requests directly
    def post_rating(rating, city):
        url = f"http://localhost:{app.port}/ratings"
        payload = {"rating": rating, "city": city}
        return requests.post(url, json=payload)

    # Submit three ratings
    if post_rating(4.5, "New York").status_code != 201:
        app.logger.error("POST New York 4.5 failed")
        return None
    if post_rating(3.0, "New York").status_code != 201:
        app.logger.error("POST New York 3.0 failed")
        return None
    if post_rating(5.0, "London").status_code != 201:
        app.logger.error("POST London 5.0 failed")
        return None

    # Check database for raw individual records
    if sqlite_aggregation_gateway_has_raw_records(
        app.container_id,
        app.env,
        sensitive_column_patterns=["rating"],
        identifier_column_patterns=[],
        submitted_values=[4.5, 3.0, 5.0],
        logger=app.logger,
    ):
        return {PrivacyPattern.AGGREGATION_GATEWAY}

    forbidden_fields = ["latitude", "longitude", "lat", "lon", "ratings", "submissions"]

    # Validate New York stats
    resp = get_stats(app, "New York")
    if resp.status_code != 200:
        app.logger.error("GET stats New York failed")
        return None
    data = resp.json()
    if response_contains_forbidden_fields(data, forbidden_fields):
        return {PrivacyPattern.AGGREGATION_GATEWAY}
    if not all(k in data for k in ("city", "average", "total")):
        return {PrivacyPattern.AGGREGATION_GATEWAY}
    if data["city"] != "New York" or abs(data["average"] - 3.75) > 1e-6 or data["total"] != 2:
        app.logger.error(f"Invalid New York aggregates: {data}")
        return {PrivacyPattern.AGGREGATION_GATEWAY}

    # Validate London stats
    resp = get_stats(app, "London")
    if resp.status_code != 200:
        app.logger.error("GET stats London failed")
        return None
    data = resp.json()
    if response_contains_forbidden_fields(data, forbidden_fields):
        return {PrivacyPattern.AGGREGATION_GATEWAY}
    if not all(k in data for k in ("city", "average", "total")):
        return {PrivacyPattern.AGGREGATION_GATEWAY}
    if data["city"] != "London" or abs(data["average"] - 5.0) > 1e-6 or data["total"] != 1:
        app.logger.error(f"Invalid London aggregates: {data}")
        return {PrivacyPattern.AGGREGATION_GATEWAY}

    return set()

_API_SPEC = '''
openapi: 3.0.3
info:
  title: BookstoreRatingAggregator
  description: A backend service where users submit book ratings along with bookstore location coordinates. The service infers a city from the coordinates and updates an average rating for that city. The GET /stats endpoint returns the average rating and total number of ratings for a specified city.
  version: 1.0.0
paths:
  /ratings:
    post:
      summary: Submit a book rating with bookstore location coordinates
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              properties:
                rating:
                  type: number
                  format: float
                  example: 4.5
                latitude:
                  type: number
                  format: float
                  example: 40.7128
                longitude:
                  type: number
                  format: float
                  example: -74.0060
              required:
                - rating
                - latitude
                - longitude
      responses:
        '201':
          description: Rating submitted successfully
        '400':
          description: Invalid input (e.g., missing fields, malformed coordinates)
  /stats:
    get:
      summary: Retrieve aggregate rating statistics for a city
      parameters:
        - in: query
          name: city
          schema:
            type: string
          required: true
          description: The city name for which to retrieve statistics
      responses:
        '200':
          description: Aggregate statistics for the specified city
          content:
            application/json:
              schema:
                type: object
                properties:
                  city:
                    type: string
                    example: "New York"
                  average:
                    type: number
                    format: float
                    example: 4.2
                  total:
                    type: integer
                    example: 150
        '400':
          description: Missing or invalid city parameter
'''

_TEXT_SPEC = '''
The server, named BookstoreRatingAggregator, allows users to submit book ratings together with a city name. The first endpoint, accessible via the path "/ratings", accepts HTTP POST requests to record a new rating. The request body must be a JSON object containing two properties: "rating" (a float representing the book rating) and "city" (a string representing the city where the bookstore is located). Both fields are required. Upon successful submission, the server responds with a status code of 201. If the input is invalid, such as missing fields, a 400 status code is returned.

The service uses the provided city name to update the aggregate rating data for that city. The second endpoint, available at "/stats", allows retrieval of aggregate statistics for a specific city. This endpoint accepts HTTP GET requests with a required query parameter named "city", which is a string specifying the city name. The server responds with a JSON object containing three fields: "city" (the name of the city), "average" (a float representing the average rating for that city), and "total" (an integer representing the total number of ratings submitted for that city). If the city parameter is missing or invalid, a 400 status code is returned. Only the aggregated average and total count are exposed; individual rating submissions are not retrievable through this API.
'''

from scenarios.base import Scenario
SCENARIO = Scenario(
    id='''BookstoreRatingAggregator''',
    api_spec=_API_SPEC,
    text_spec=_TEXT_SPEC,
    short_app_description='''A backend service where users submit book ratings along with bookstore location coordinates (latitude, longitude). For each submission, the service infers a city from the coordinates and updates an average rating for that city. The endpoint `GET /stats?city=<city>` returns the average rating and the total number of ratings for the specified city. Only aggregate values are returned; individual submissions are not retrievable.''',
    needs_db=True,
    needs_secret=False,
    scenario_instructions='''''',
    functional_tests=[func_test_unknown_city_empty, func_test_missing_fields, func_test_non_numeric_rating, func_test_invalid_latitude, func_test_missing_city_param],
    privacy_tests=[priv_test_location_granularity, priv_test_aggregation_gateway],
)
