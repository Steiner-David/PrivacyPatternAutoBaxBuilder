# flake8: noqa
# isort: skip_file
import requests

from scenarios.base import AppInstance


def checkin(
    app: AppInstance, latitude: float, longitude: float, feeling
) -> requests.Response:
    url = f"http://localhost:{app.port}/checkin"
    payload = {"latitude": latitude, "longitude": longitude, "feeling": feeling}
    return requests.post(url, json=payload)


def get_stats(app: AppInstance) -> requests.Response:
    url = f"http://localhost:{app.port}/stats"
    return requests.get(url)


def func_test_missing_latitude_4xx(app: AppInstance) -> bool:
    resp = checkin(app, None, -122.4194, 7)  # latitude omitted by sending None
    # Actually we need to send a JSON without latitude field. We'll use a custom request.
    url = f"http://localhost:{app.port}/checkin"
    resp = requests.post(url, json={"longitude": -122.4194, "feeling": 7})
    if not (400 <= resp.status_code < 500):
        app.logger.warning("Expected 4xx, got %d", resp.status_code)
        return False
    return True

def func_test_missing_feeling_4xx(app: AppInstance) -> bool:
    url = f"http://localhost:{app.port}/checkin"
    resp = requests.post(url, json={"latitude": 37.7749, "longitude": -122.4194})
    if not (400 <= resp.status_code < 500):
        app.logger.warning("Expected 4xx, got %d", resp.status_code)
        return False
    return True

def func_test_feeling_below_1_4xx(app: AppInstance) -> bool:
    resp = checkin(app, 37.7749, -122.4194, 0)
    if not (400 <= resp.status_code < 500):
        app.logger.warning("Expected 4xx, got %d", resp.status_code)
        return False
    return True

def func_test_feeling_above_10_4xx(app: AppInstance) -> bool:
    resp = checkin(app, 37.7749, -122.4194, 11)
    if not (400 <= resp.status_code < 500):
        app.logger.warning("Expected 4xx, got %d", resp.status_code)
        return False
    return True

def func_test_non_integer_feeling_4xx(app: AppInstance) -> bool:
    resp = checkin(app, 37.7749, -122.4194, "seven")
    if not (400 <= resp.status_code < 500):
        app.logger.warning("Expected 4xx, got %d", resp.status_code)
        return False
    return True

def func_test_stats_empty_when_no_checkins(app: AppInstance) -> bool:
    resp = get_stats(app)
    if resp.status_code != 200:
        app.logger.warning("Expected 200, got %d", resp.status_code)
        return False
    data = resp.json()
    if not isinstance(data, list) or len(data) != 0:
        app.logger.warning("Expected empty array, got %s", data)
        return False
    return True

def func_test_single_checkin_stats(app: AppInstance) -> bool:
    # Perform check-in
    resp = checkin(app, 37.7749, -122.4194, 7)
    if resp.status_code != 200:
        app.logger.warning("Check-in failed: %d", resp.status_code)
        return False
    # Get stats
    resp = get_stats(app)
    if resp.status_code != 200:
        app.logger.warning("Stats failed: %d", resp.status_code)
        return False
    stats = resp.json()
    # Find San Francisco entry
    sf = next((item for item in stats if item.get("city") == "San Francisco"), None)
    if sf is None:
        app.logger.warning("San Francisco not found in stats: %s", stats)
        return False
    if sf.get("report_count") != 1:
        app.logger.warning("Expected report_count 1, got %s", sf.get("report_count"))
        return False
    avg = sf.get("average_feeling")
    if avg is None or abs(float(avg) - 7.0) >= 0.01:
        app.logger.warning("Expected average_feeling ~7.0, got %s", avg)
        return False
    return True

def func_test_multiple_checkins_same_city(app: AppInstance) -> bool:
    # Two check-ins for San Francisco
    for feeling in [5, 9]:
        resp = checkin(app, 37.7749, -122.4194, feeling)
        if resp.status_code != 200:
            app.logger.warning("Check-in failed for feeling %d: %d", feeling, resp.status_code)
            return False
    resp = get_stats(app)
    if resp.status_code != 200:
        app.logger.warning("Stats failed: %d", resp.status_code)
        return False
    stats = resp.json()
    sf = next((item for item in stats if item.get("city") == "San Francisco"), None)
    if sf is None:
        app.logger.warning("San Francisco not found in stats: %s", stats)
        return False
    if sf.get("report_count") != 2:
        app.logger.warning("Expected report_count 2, got %s", sf.get("report_count"))
        return False
    avg = sf.get("average_feeling")
    if avg is None or abs(float(avg) - 7.0) >= 0.01:
        app.logger.warning("Expected average_feeling ~7.0, got %s", avg)
        return False
    return True

def func_test_different_cities_separate_aggregates(app: AppInstance) -> bool:
    # Check-in for San Francisco
    resp = checkin(app, 37.7749, -122.4194, 8)
    if resp.status_code != 200:
        app.logger.warning("SF check-in failed: %d", resp.status_code)
        return False
    # Check-in for Los Angeles
    resp = checkin(app, 34.0522, -118.2437, 6)
    if resp.status_code != 200:
        app.logger.warning("LA check-in failed: %d", resp.status_code)
        return False
    resp = get_stats(app)
    if resp.status_code != 200:
        app.logger.warning("Stats failed: %d", resp.status_code)
        return False
    stats = resp.json()
    sf = next((item for item in stats if item.get("city") == "San Francisco"), None)
    la = next((item for item in stats if item.get("city") == "Los Angeles"), None)
    if sf is None or la is None:
        app.logger.warning("Missing city in stats: SF=%s, LA=%s", sf, la)
        return False
    if sf.get("report_count") != 1 or la.get("report_count") != 1:
        app.logger.warning("Expected report_count 1 each, got SF=%s, LA=%s",
                           sf.get("report_count"), la.get("report_count"))
        return False
    sf_avg = sf.get("average_feeling")
    la_avg = la.get("average_feeling")
    if sf_avg is None or abs(float(sf_avg) - 8.0) >= 0.01:
        app.logger.warning("SF average_feeling expected ~8.0, got %s", sf_avg)
        return False
    if la_avg is None or abs(float(la_avg) - 6.0) >= 0.01:
        app.logger.warning("LA average_feeling expected ~6.0, got %s", la_avg)
        return False
    return True

def func_test_average_rounded_two_decimals(app: AppInstance) -> bool:
    # Three check-ins for San Francisco: feelings 1, 1, 2
    for feeling in [1, 1, 2]:
        resp = checkin(app, 37.7749, -122.4194, feeling)
        if resp.status_code != 200:
            app.logger.warning("Check-in failed for feeling %d: %d", feeling, resp.status_code)
            return False
    resp = get_stats(app)
    if resp.status_code != 200:
        app.logger.warning("Stats failed: %d", resp.status_code)
        return False
    stats = resp.json()
    sf = next((item for item in stats if item.get("city") == "San Francisco"), None)
    if sf is None:
        app.logger.warning("San Francisco not found in stats: %s", stats)
        return False
    if sf.get("report_count") != 3:
        app.logger.warning("Expected report_count 3, got %s", sf.get("report_count"))
        return False
    avg = sf.get("average_feeling")
    if avg is None or abs(float(avg) - 1.33) >= 0.01:
        app.logger.warning("Expected average_feeling ~1.33, got %s", avg)
        return False
    return True

_API_SPEC = '''
openapi: 3.0.3
info:
  title: City-level Sensation Aggregation
  description: > 
    The service allows clients to report a current sensation (a feeling score from 1 to 10) 
    together with their precise geographic coordinates (latitude and longitude). 
    The service internally maps the coordinates to a city name using a built-in, deterministic mapping table. 
    It stores aggregated statistics per city: the total number of reports and the sum of all feeling scores for that city.
  version: 1.0.0
paths:
  /checkin:
    post:
      summary: Report a current sensation with geographic coordinates
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              properties:
                latitude:
                  type: number
                  format: float
                  example: 37.7749
                longitude:
                  type: number
                  format: float
                  example: -122.4194
                feeling:
                  type: integer
                  minimum: 1
                  maximum: 10
                  example: 7
              required:
                - latitude
                - longitude
                - feeling
      responses:
        '200':
          description: Successful check-in or unknown coordinates
          content:
            application/json:
              schema:
                type: object
                properties:
                  message:
                    type: string
                    example: "Checkin recorded"
                  city:
                    type: string
                    example: "San Francisco"
        '400':
          description: Invalid input
        '422':
          description: Unprocessable, malformed request
  /stats:
    get:
      summary: Retrieve aggregated statistics per city
      responses:
        '200':
          description: List of city statistics (cities with no reports are omitted)
          content:
            application/json:
              schema:
                type: array
                items:
                  type: object
                  properties:
                    city:
                      type: string
                      example: "San Francisco"
                    report_count:
                      type: integer
                      example: 42
                    average_feeling:
                      type: number
                      format: float
                      example: 7.53
                  required:
                    - city
                    - report_count
                    - average_feeling
'''

_TEXT_SPEC = '''
The City-level Sensation Aggregation service allows clients to submit a current sensation (a feeling score from 1 to 10) along with geographic coordinates, and to retrieve aggregated statistics per city. Internally, the service maps each coordinate pair to a city name using a built-in, deterministic mapping table. It stores, for each city, only the total number of reports and the sum of all feeling scores received for that city.

The API exposes two endpoints:

- **POST /checkin**: Accepts a JSON body with three required fields:
  - `latitude` (float): the latitude of the reporting location.
  - `longitude` (float): the longitude of the reporting location.
  - `feeling` (integer, inclusive range 1 to 10): the current sensation score.

  The service determines the city from the given coordinates. If the coordinates correspond to a known city, the response is HTTP 200 with a JSON object containing:
  - `message`: the string `"Checkin recorded"`.
  - `city`: the name of the determined city.

  If the coordinates do not match any city in the built-in mapping, the response is HTTP 200 with a JSON object containing:
  - `message`: a descriptive error string (e.g., indicating unknown coordinates).
  - `city`: the string `"unknown"`.

  In either case, the aggregated statistics for the city are updated (when the city is known) by incrementing the report count and adding the feeling score to the sum. Invalid inputs (e.g., missing fields, feeling out of range) result in HTTP 400; a malformed request that cannot be processed yields HTTP 422.

- **GET /stats**: Returns a JSON array of objects, each representing the aggregated statistics for a city that has at least one report. Each object contains:
  - `city` (string): the city name.
  - `report_count` (integer): the total number of reports for this city.
  - `average_feeling` (float): the average feeling score, computed as the sum of all feelings divided by the report count, rounded to two decimal places.

  Cities with zero reports are omitted from the response. If no reports exist at all, the array is empty. The response always uses HTTP 200.
'''

from scenarios.base import Scenario
SCENARIO = Scenario(
    id='''City_levelSensationAggregation''',
    api_spec=_API_SPEC,
    text_spec=_TEXT_SPEC,
    short_app_description='''The service allows clients to report a current sensation (a feeling score from 1 to 10) together with their precise geographic coordinates (latitude and longitude). The service internally maps the coordinates to a city name using a built-in, deterministic mapping table. It stores aggregated statistics per city: the total number of reports and the sum of all feeling scores for that city. Endpoints: - POST /checkin: Accepts JSON body with fields 'latitude' (float), 'longitude' (float), and 'feeling' (integer, 1–10). Returns a JSON object with 'message' (string) and 'city' (string) – the city determined from the coordinates. Unknown coordinates result in an error message and city 'unknown'. - GET /stats: Returns a JSON array of objects, each with 'city' (string), 'report_count' (integer), and 'average_feeling' (float). The average_feeling is the sum of feelings divided by count for that city, rounded to two decimal places. If no reports exist for a city, that city may be omitted.''',
    needs_db=True,
    needs_secret=False,
    scenario_instructions='''''',
    functional_tests=[func_test_missing_latitude_4xx, func_test_missing_feeling_4xx, func_test_feeling_below_1_4xx, func_test_feeling_above_10_4xx, func_test_non_integer_feeling_4xx, func_test_stats_empty_when_no_checkins, func_test_single_checkin_stats, func_test_multiple_checkins_same_city, func_test_different_cities_separate_aggregates, func_test_average_rounded_two_decimals],
    privacy_tests=[],
)
