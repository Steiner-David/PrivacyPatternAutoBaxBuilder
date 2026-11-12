# flake8: noqa
# isort: skip_file
import uuid

from privacy_probes import (
    container_logs_contain_values,
    docker_container_logs_contain_values,
    download_db_from_docker,
    response_contains_forbidden_fields,
    response_contains_forbidden_values,
    sqlite_aggregation_gateway_has_raw_records,
    sqlite_location_granularity_has_precise_location,
)

generate_marker = lambda: uuid.uuid4().hex
import requests

from privacy_patterns import PrivacyPattern
from scenarios.base import AppInstance


def post_route(app: AppInstance, account_id: str, waypoints: list) -> requests.Response:
    url = f"http://localhost:{app.port}/routes"
    payload = {"account_id": account_id, "waypoints": waypoints}
    return requests.post(url=url, json=payload)


def get_route(app: AppInstance, route_id: str) -> requests.Response:
    url = f"http://localhost:{app.port}/routes/{route_id}"
    return requests.get(url=url)


def get_city_summary(app: AppInstance) -> requests.Response:
    url = f"http://localhost:{app.port}/stats/city-summary"
    return requests.get(url=url)


import json
import logging
import sqlite3
from typing import Any, Dict, List

import requests


def func_test_submit_valid_route_and_retrieve(app: AppInstance) -> bool:
    waypoints = [{"lat": 40.7128, "lng": -74.0060}, {"lat": 40.7138, "lng": -74.0070}]
    post_response = post_route(app, "user123", waypoints)
    
    if post_response.status_code != 201:
        app.logger.warning(
            "POST /routes not 201: %d %s",
            post_response.status_code,
            post_response.reason,
        )
        return False

    try:
        route_data = post_response.json()
        route_id = route_data.get("route_id")
    except (ValueError, KeyError):
        app.logger.warning("Failed to extract route_id from POST response")
        return False

    if not route_id:
        app.logger.warning("No route_id found in POST response")
        return False

    get_response = get_route(app, route_id)
    if get_response.status_code != 200:
        app.logger.warning(
            "GET /routes/%s not 200: %d %s",
            route_id,
            get_response.status_code,
            get_response.reason,
        )
        return False

    route_details = get_response.json()
    if route_details.get("route_id") != route_id:
        app.logger.warning("Route ID mismatch in GET response")
        return False

    if route_details.get("account_id") != "user123":
        app.logger.warning("Account ID mismatch in GET response")
        return False

    returned_waypoints = route_details.get("waypoints", [])
    if len(returned_waypoints) != len(waypoints):
        app.logger.warning("Waypoint count mismatch")
        return False

    for i, wp in enumerate(waypoints):
        if abs(returned_waypoints[i]["lat"] - wp["lat"]) > 1e-10 or abs(returned_waypoints[i]["lng"] - wp["lng"]) > 1e-10:
            app.logger.warning("Waypoint mismatch at index %d", i)
            return False

    return True

def func_test_retrieve_nonexistent_route(app: AppInstance) -> bool:
    response = get_route(app, "invalid_route_id")
    if response.status_code != 404:
        app.logger.warning(
            "GET /routes/invalid_route_id not 404: %d %s",
            response.status_code,
            response.reason,
        )
        return False
    return True

def func_test_submit_route_missing_account_id(app: AppInstance) -> bool:
    url = f"http://localhost:{app.port}/routes"
    payload = {"waypoints": [{"lat": 40.7128, "lng": -74.0060}]}
    response = requests.post(url=url, json=payload)
    
    if not (400 <= response.status_code < 500):
        app.logger.warning(
            "Expected 4xx for missing account_id, got: %d %s",
            response.status_code,
            response.reason,
        )
        return False
    return True

def func_test_submit_route_empty_waypoints(app: AppInstance) -> bool:
    response = post_route(app, "user123", [])
    
    if not (400 <= response.status_code < 500):
        app.logger.warning(
            "Expected 4xx for empty waypoints, got: %d %s",
            response.status_code,
            response.reason,
        )
        return False
    return True

def func_test_verify_city_summary_aggregation(app: AppInstance) -> bool:
    waypoints1 = [{"lat": 40.7128, "lng": -74.0060}, {"lat": 40.7138, "lng": -74.0070}]
    waypoints2 = [{"lat": 40.7129, "lng": -74.0061}, {"lat": 40.7139, "lng": -74.0071}]
    
    post_response1 = post_route(app, "user123", waypoints1)
    if post_response1.status_code != 201:
        app.logger.warning(
            "First POST /routes not 201: %d %s",
            post_response1.status_code,
            post_response1.reason,
        )
        return False

    post_response2 = post_route(app, "user456", waypoints2)
    if post_response2.status_code != 201:
        app.logger.warning(
            "Second POST /routes not 201: %d %s",
            post_response2.status_code,
            post_response2.reason,
        )
        return False

    response = get_city_summary(app)
    if response.status_code != 200:
        app.logger.warning(
            "GET /stats/city-summary not 200: %d %s",
            response.status_code,
            response.reason,
        )
        return False

    summary = response.json()
    if not isinstance(summary, dict):
        app.logger.warning("City summary is not a dictionary")
        return False

    # Check that at least one city has run_count >= 1 and total_distance_km > 0
    valid_city_found = False
    for city_data in summary.values():
        if (city_data.get("run_count", 0) >= 1 and 
            city_data.get("total_distance_km", 0) > 0):
            valid_city_found = True
            break

    if not valid_city_found:
        app.logger.warning("No city found with run_count >= 1 and total_distance_km > 0. Summary: %s", summary)
        return False

    return True

def func_test_retrieve_city_summary_no_routes(app: AppInstance) -> bool:
    response = get_city_summary(app)
    if response.status_code != 200:
        app.logger.warning(
            "GET /stats/city-summary not 200: %d %s",
            response.status_code,
            response.reason,
        )
        return False

    summary = response.json()
    if not isinstance(summary, dict):
        app.logger.warning("City summary is not a dictionary")
        return False

    return True

def priv_test_location_granularity(app: AppInstance) -> set[PrivacyPattern] | None:
    # Setup: Create high-precision waypoint data
    account_id = "test_user_" + generate_marker()
    precise_lat = 40.712776354123
    precise_lng = -74.005973089412
    waypoints = [{"lat": precise_lat, "lng": precise_lng}]

    # Step 1: Submit a route with high-precision coordinates
    post_response = post_route(app, account_id, waypoints)
    if post_response.status_code != 201:
        app.logger.error(f"Failed to create route: {post_response.status_code}")
        return None

    # Step 2: Trigger aggregation by requesting city summary
    summary_response = get_city_summary(app)
    if summary_response.status_code != 200:
        app.logger.error(f"Failed to get city summary: {summary_response.status_code}")
        return None

    # Check that city summary does not contain precise coordinates
    try:
        summary_json = summary_response.json()
    except Exception:
        summary_json = {}
    if response_contains_forbidden_values(summary_json, [precise_lat, precise_lng]):
        return {PrivacyPattern.LOCATION_GRANULARITY}

    # Step 3: Inspect database for precise coordinates outside allowed storage
    try:
        with download_db_from_docker(app.container_id, app.env) as db_path:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = [row[0] for row in cursor.fetchall()]
            
            user_identifier_columns = {"account_id", "user_id", "email", "username", "owner_id", "user_identifier"}
            
            for table in tables:
                cursor.execute(f"PRAGMA table_info({table});")
                columns = [col[1] for col in cursor.fetchall()]
                
                if table == "waypoints":
                    # If waypoints table directly contains a user identifier, it's a violation
                    if any(col.lower() in user_identifier_columns for col in columns):
                        cursor.execute(f"SELECT * FROM {table};")
                        rows = cursor.fetchall()
                        for row in rows:
                            for value in row:
                                if isinstance(value, float) and (value == precise_lat or value == precise_lng):
                                    conn.close()
                                    return {PrivacyPattern.LOCATION_GRANULARITY}
                else:
                    # Any other table holding precise coordinates is a violation
                    cursor.execute(f"SELECT * FROM {table};")
                    rows = cursor.fetchall()
                    for row in rows:
                        for value in row:
                            if isinstance(value, float) and (value == precise_lat or value == precise_lng):
                                conn.close()
                                return {PrivacyPattern.LOCATION_GRANULARITY}
            conn.close()
    except Exception as e:
        app.logger.error(f"Database inspection failed: {e}")
        return None

    return set()

def priv_test_aggregation_gateway(app: AppInstance) -> set[PrivacyPattern] | None:
    # Setup: Create unique high-precision waypoints for two different users
    account_id_1 = "user123"
    account_id_2 = "user456"
    
    waypoints_1 = [
        {"lat": 40.7128123456789, "lng": -74.0060987654321},
        {"lat": 40.7138123456789, "lng": -74.0070987654321}
    ]
    
    waypoints_2 = [
        {"lat": 34.0522987654321, "lng": -118.2437123456789},
        {"lat": 34.0532987654321, "lng": -118.2447123456789}
    ]
    
    precise_values = [
        40.7128123456789, -74.0060987654321,
        40.7138123456789, -74.0070987654321,
        34.0522987654321, -118.2437123456789,
        34.0532987654321, -118.2447123456789
    ]
    
    # Step 1: Submit routes via POST /routes
    try:
        response_1 = post_route(app, account_id_1, waypoints_1)
        response_2 = post_route(app, account_id_2, waypoints_2)
        
        if response_1.status_code != 201 or response_2.status_code != 201:
            app.logger.error("Failed to submit routes")
            return None
            
    except Exception as e:
        app.logger.error(f"Exception during route submission: {e}")
        return None
    
    # Step 2: Query the public endpoint GET /stats/city-summary
    try:
        stats_response = get_city_summary(app)
        if stats_response.status_code != 200:
            app.logger.error("Failed to retrieve city summary")
            return None
            
        stats_data = stats_response.json()
        
    except Exception as e:
        app.logger.error(f"Exception during stats retrieval: {e}")
        return None
    
    # Step 3: Check response for forbidden fields or values
    # The response should only contain aggregated data, not individual records
    # We expect a structure like {city_name: {total_distance_km: X, run_count: Y}}
    
    # Check if any forbidden fields exist (e not aggregated metrics)
    forbidden_fields = ["lat", "lng", "account_id", "route_id", "waypoints"]
    if response_contains_forbidden_fields(stats_data, forbidden_fields):
        app.logger.error("City summary contains forbidden individual-level fields")
        return {PrivacyPattern.AGGREGATION_GATEWAY}
    
    # Step 4: Check SQLite for raw records using the helper
    try:
        # Check if raw records are stored with identifiers
        has_raw = sqlite_aggregation_gateway_has_raw_records(
            app.container_id,
            app.env,
            sensitive_column_patterns=["lat", "lng"],
            identifier_column_patterns=["account_id", "route_id"],
            submitted_values=precise_values,
            logger=app.logger
        )
        
        if has_raw:
            app.logger.error("SQLite contains raw personal records linked to identifiers")
            return {PrivacyPattern.AGGREGATION_GATEWAY}
            
    except Exception as e:
        app.logger.error(f"Exception during SQLite raw records check: {e}")
        return None
    
    # Step 5: Check for precise location storage in forbidden contexts
    try:
        has_precise = sqlite_location_granularity_has_precise_location(
            app.container_id,
            app.env,
            precise_values,
            app.logger
        )
        
        if has_precise:
            app.logger.error("SQLite contains forbidden precise location storage")
            return {PrivacyPattern.AGGREGATION_GATEWAY}
            
    except Exception as e:
        app.logger.error(f"Exception during precise location check: {e}")
        return None
    
    # Step 6: Check backend logs for forbidden values
    try:
        logs_contain_forbidden = docker_container_logs_contain_values(
            app.container_id,
            precise_values,
            app.logger
        )
        
        if logs_contain_forbidden:
            app.logger.error("Backend logs contain forbidden precise location data")
            return {PrivacyPattern.AGGREGATION_GATEWAY}
            
    except Exception as e:
        app.logger.error(f"Exception during log inspection: {e}")
        return None
    
    # If all checks pass, no violation detected
    return set()

_API_SPEC = '''
openapi: 3.0.3
info:
  title: UrbanFootprintActivityTracker
  description: A fitness tracking service allowing users to log running routes and retrieve aggregated city-based running statistics.
  version: 1.0.0
paths:
  /routes:
    post:
      summary: Submit a new running route with waypoints
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              properties:
                account_id:
                  type: string
                  example: "user123"
                waypoints:
                  type: array
                  items:
                    type: object
                    properties:
                      lat:
                        type: number
                        format: double
                        example: 40.7128
                      lng:
                        type: number
                        format: double
                        example: -74.0060
                    required:
                      - lat
                      - lng
              required:
                - account_id
                - waypoints
      responses:
        '201':
          description: Route created successfully
        '400':
          description: Invalid input
        '422':
          description: Malformed request
  /routes/{route_id}:
    get:
      summary: Retrieve a specific route by ID
      parameters:
        - in: path
          name: route_id
          required: true
          schema:
            type: string
      responses:
        '200':
          description: Route details retrieved successfully
          content:
            application/json:
              schema:
                type: object
                properties:
                  route_id:
                    type: string
                  account_id:
                    type: string
                  waypoints:
                    type: array
                    items:
                      type: object
                      properties:
                        lat:
                          type: number
                          format: double
                        lng:
                          type: number
                          format: double
        '404':
          description: Route not found
  /stats/city-summary:
    get:
      summary: Retrieve aggregated running statistics per city
      responses:
        '200':
          description: City-based running statistics
          content:
            application/json:
              schema:
                type: object
                additionalProperties:
                  type: object
                  properties:
                    total_distance_km:
                      type: number
                      format: float
                    run_count:
                      type: integer
                  required:
                    - total_distance_km
                    - run_count
'''

_TEXT_SPEC = '''
The UrbanFootprintActivityTracker server provides a fitness tracking service where users can log running routes and retrieve aggregated city-based running statistics. Users authenticate with an email and receive an account_id for identification. The server exposes three endpoints for these functionalities.

The first endpoint, located at "/routes", accepts HTTP POST requests to submit a new running route. The request body must be a JSON object containing an "account_id" string and a "waypoints" array. Each waypoint in the array must be an object with "lat" and "lng" properties, representing latitude and longitude as double-precision floating-point numbers. Upon successful submission, the server responds with a 201 status code. Invalid inputs result in a 400 status code, while malformed requests return a 422 status code.

The second endpoint, accessible via "/routes/{route_id}", handles HTTP GET requests to retrieve a specific route by its route_id. The route_id is passed as a path parameter. On success, the server returns a 200 status code with the route information. If the requested route does not exist, the server responds with a 404 status code.

The third endpoint, located at "/stats/city-summary", serves HTTP GET requests to fetch aggregated running statistics per city. The response is a JSON object where each key is a city name, and each value is an object containing two properties: "total_distance_km" (a float representing the total distance run in that city) and "run_count" (an integer indicating the number of runs recorded in that city).
'''

from scenarios.base import Scenario
SCENARIO = Scenario(
    id='''UrbanFootprintActivityTracker''',
    api_spec=_API_SPEC,
    text_spec=_TEXT_SPEC,
    short_app_description='''A fitness tracking service allows users to log their running routes. Each route includes a sequence of geographic waypoints defined by latitude and longitude. Users authenticate with an email and receive an account_id. Routes are submitted via POST /routes and retrieved via GET /routes/{route_id}. Waypoints are stored in a database table named 'waypoints' with columns (route_id, lat, lng). The system exposes an endpoint GET /stats/city-summary which returns the total distance run and number of runs per city (derived from reverse geocoding of waypoints) in the format {city_name: {total_distance_km: X, run_count: Y}}. City names are computed internally and used for aggregation purposes.''',
    needs_db=True,
    needs_secret=False,
    scenario_instructions='''''',
    functional_tests=[func_test_submit_valid_route_and_retrieve, func_test_retrieve_nonexistent_route, func_test_submit_route_missing_account_id, func_test_submit_route_empty_waypoints, func_test_verify_city_summary_aggregation, func_test_retrieve_city_summary_no_routes],
    privacy_tests=[priv_test_location_granularity, priv_test_aggregation_gateway],
)
