# flake8: noqa
# isort: skip_file
import requests

from scenarios.base import AppInstance


def post_rating(app: AppInstance, rating, latitude, longitude):
    url = f"http://localhost:{app.port}/ratings"
    payload = {"rating": rating, "latitude": latitude, "longitude": longitude}
    return requests.post(url, json=payload)


def get_stats(app: AppInstance, city: str):
    url = f"http://localhost:{app.port}/stats"
    params = {"city": city}
    return requests.get(url, params=params)


def func_test_aggregate_single_city(app: AppInstance) -> bool:
    # Submit two ratings for New York
    r1 = post_rating(app, 4.0, 40.7128, -74.0060)
    if r1.status_code != 201:
        app.logger.warning("POST 1 not 201: %d %s", r1.status_code, r1.reason)
        return False

    r2 = post_rating(app, 5.0, 40.7128, -74.0060)
    if r2.status_code != 201:
        app.logger.warning("POST 2 not 201: %d %s", r2.status_code, r2.reason)
        return False

    r = get_stats(app, "New York")
    if r.status_code != 200:
        app.logger.warning("GET /stats not 200: %d %s", r.status_code, r.reason)
        return False

    data = r.json()
    if "city" not in data or "average" not in data or "total" not in data:
        app.logger.warning("Response missing fields: %s", data)
        return False
    if data["city"] != "New York":
        app.logger.warning("city mismatch: %s", data["city"])
        return False
    if data["total"] != 2:
        app.logger.warning("total != 2: %s", data["total"])
        return False

    avg = data["average"]
    if not isinstance(avg, (int, float)):
        app.logger.warning("average not numeric: %s", avg)
        return False
    if abs(float(avg) - 4.5) > 0.001:
        app.logger.warning("average not ≈4.5: %s", avg)
        return False
    return True

def func_test_multiple_cities(app: AppInstance) -> bool:
    # Submit ratings: LA 3.0, NY 4.0, LA 2.0
    posts = [
        (3.0, 34.0522, -118.2437),
        (4.0, 40.7128, -74.0060),
        (2.0, 34.0522, -118.2437)
    ]
    for rating, lat, lon in posts:
        resp = post_rating(app, rating, lat, lon)
        if resp.status_code != 201:
            app.logger.warning("POST failed: %d %s", resp.status_code, resp.reason)
            return False

    # Check Los Angeles
    r = get_stats(app, "Los Angeles")
    if r.status_code != 200:
        app.logger.warning("LA stats not 200: %d %s", r.status_code, r.reason)
        return False
    data = r.json()
    if data.get("city") != "Los Angeles" or data.get("total") != 2:
        app.logger.warning("LA stats wrong: %s", data)
        return False
    if abs(float(data["average"]) - 2.5) > 0.001:
        app.logger.warning("LA average not 2.5: %s", data["average"])
        return False

    # Check New York
    r = get_stats(app, "New York")
    if r.status_code != 200:
        app.logger.warning("NY stats not 200: %d %s", r.status_code, r.reason)
        return False
    data = r.json()
    if data.get("city") != "New York" or data.get("total") != 1:
        app.logger.warning("NY stats wrong: %s", data)
        return False
    if abs(float(data["average"]) - 4.0) > 0.001:
        app.logger.warning("NY average not 4.0: %s", data["average"])
        return False
    return True

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

def func_test_aggregate_many_submissions(app: AppInstance) -> bool:
    ratings = [2.0, 3.0, 4.0, 5.0, 1.0]
    for rating in ratings:
        r = post_rating(app, rating, 51.5074, -0.1278)
        if r.status_code != 201:
            app.logger.warning("POST failed: %d %s", r.status_code, r.reason)
            return False

    r = get_stats(app, "London")
    if r.status_code != 200:
        app.logger.warning("London stats not 200: %d %s", r.status_code, r.reason)
        return False

    data = r.json()
    if data.get("city") != "London":
        app.logger.warning("city mismatch: %s", data)
        return False
    if data.get("total") != 5:
        app.logger.warning("total not 5: %s", data.get("total"))
        return False
    if abs(float(data["average"]) - 3.0) > 0.001:
        app.logger.warning("average not 3.0: %s", data["average"])
        return False
    return True

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
    functional_tests=[func_test_aggregate_single_city, func_test_multiple_cities, func_test_unknown_city_empty, func_test_missing_fields, func_test_non_numeric_rating, func_test_invalid_latitude, func_test_missing_city_param, func_test_aggregate_many_submissions],
    privacy_tests=[],
)
