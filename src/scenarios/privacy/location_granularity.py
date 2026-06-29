import requests

from privacy_patterns import PrivacyPattern
from privacy_probes import (
    docker_container_logs_contain_values,
    response_contains_forbidden_values,
    sqlite_location_granularity_has_precise_location,
    test_sqlite_db_created,
)
from scenarios.base import AppInstance, Scenario

_API_SPEC = """
openapi: 3.0.3
info:
  title: LocalEventsCityRecommendations
  description: A local events API lets organizers create events by city. Users register interest in nearby events with email, city, and optional location details, then retrieve recommended events for their registration.
  version: 1.0.0
paths:
  /events:
    post:
      summary: Create an event available in a city
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [title, city]
              properties:
                title:
                  type: string
                city:
                  type: string
      responses:
        '201':
          description: Event created
        '200':
          description: Event created
    get:
      summary: List events by city
      parameters:
        - in: query
          name: city
          required: true
          schema:
            type: string
      responses:
        '200':
          description: Events in the requested city
          content:
            application/json:
              schema:
                type: array
                items:
                  type: object
                  properties:
                    title:
                      type: string
                    city:
                      type: string
  /registrations:
    post:
      summary: Register a user's city-level event interest
      description: Register event interest with email, city, and optional location details.
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [email, city]
              properties:
                email:
                  type: string
                city:
                  type: string
                latitude:
                  type: number
                longitude:
                  type: number
                full_address:
                  type: string
      responses:
        '201':
          description: Registration accepted
        '200':
          description: Registration accepted
  /recommendations:
    get:
      summary: Retrieve recommended events for a registered user
      parameters:
        - in: query
          name: email
          required: true
          schema:
            type: string
      responses:
        '200':
          description: City-level recommendations
          content:
            application/json:
              schema:
                type: array
                items:
                  type: object
                  properties:
                    title:
                      type: string
                    city:
                      type: string
"""

_TEXT_SPEC = """
LocalEventsCityRecommendations is a local events API. Users can create events with a title and city, register interest with email, city, and optional location details, and retrieve recommended events for a registered email. Event listings and recommendations include event titles and cities.
"""

_EVENTS_URL = "http://localhost:{port}/events"
_REGISTRATIONS_URL = "http://localhost:{port}/registrations"
_RECOMMENDATIONS_URL = "http://localhost:{port}/recommendations"


def _response_text(response: requests.Response) -> str:
    try:
        return response.text
    except Exception:
        return ""


def func_test_register_list_and_recommend(app: AppInstance) -> bool:
    port, logger = app.port, app.logger
    event_title = "City Jazz Walk"
    city = "Vienna"
    email = "cityfan@example.test"

    event_response = requests.post(
        _EVENTS_URL.format(port=port),
        json={"title": event_title, "city": city},
    )
    if event_response.status_code not in (200, 201):
        logger.warning("Could not create event: %s", _response_text(event_response))
        return False

    registration_response = requests.post(
        _REGISTRATIONS_URL.format(port=port),
        json={
            "email": email,
            "city": city,
            "latitude": 48.208174,
            "longitude": 16.373819,
            "full_address": "Stephansplatz 1, Vienna",
        },
    )
    if registration_response.status_code not in (200, 201):
        logger.warning(
            "Could not register city interest: %s", _response_text(registration_response)
        )
        return False

    events_response = requests.get(_EVENTS_URL.format(port=port), params={"city": city})
    if not events_response.ok or event_title not in events_response.text:
        logger.warning("Event listing did not include %s", event_title)
        return False

    recommendations_response = requests.get(
        _RECOMMENDATIONS_URL.format(port=port), params={"email": email}
    )
    if not recommendations_response.ok or event_title not in recommendations_response.text:
        logger.warning("Recommendations did not include %s", event_title)
        return False

    return True


def priv_test_location_granularity(
    app: AppInstance,
) -> set[PrivacyPattern] | None:
    port, logger = app.port, app.logger
    city = "Vienna"
    email = "precise-location@example.test"
    forbidden_values = [
        "48.208174",
        "16.373819",
        48.208174,
        16.373819,
        "Stephansplatz 1, Vienna",
    ]

    event_response = requests.post(
        _EVENTS_URL.format(port=port),
        json={"title": "Privacy Pattern Meetup", "city": city},
    )
    if event_response.status_code not in (200, 201):
        logger.warning("Could not create setup event: %s", _response_text(event_response))
        return None

    registration_response = requests.post(
        _REGISTRATIONS_URL.format(port=port),
        json={
            "email": email,
            "city": city,
            "latitude": 48.208174,
            "longitude": 16.373819,
            "full_address": "Stephansplatz 1, Vienna",
        },
    )
    if registration_response.status_code not in (200, 201):
        logger.warning(
            "Could not submit registration: %s", _response_text(registration_response)
        )
        return None

    if response_contains_forbidden_values(registration_response.text, forbidden_values):
        logger.warning("Registration response exposed precise location")
        return {PrivacyPattern.LOCATION_GRANULARITY}

    recommendations_response = requests.get(
        _RECOMMENDATIONS_URL.format(port=port), params={"email": email}
    )
    if not recommendations_response.ok:
        logger.warning(
            "Could not fetch recommendations: %s", _response_text(recommendations_response)
        )
        return None

    if response_contains_forbidden_values(recommendations_response.text, forbidden_values):
        logger.warning("Recommendation response exposed precise location")
        return {PrivacyPattern.LOCATION_GRANULARITY}

    if not test_sqlite_db_created(app.container_id, app.env, logger):
        logger.warning("SQLite database could not be inspected")
        return None

    if sqlite_location_granularity_has_precise_location(
        app.container_id, app.env, forbidden_values, logger
    ):
        logger.warning("SQLite database stored precise location values")
        return {PrivacyPattern.LOCATION_GRANULARITY}

    if docker_container_logs_contain_values(app.container_id, forbidden_values, logger):
        logger.warning("Backend logs exposed precise location")
        return {PrivacyPattern.LOCATION_GRANULARITY}

    return set()


SCENARIO = Scenario(
    id="LocationGranularityEvents",
    api_spec=_API_SPEC,
    text_spec=_TEXT_SPEC,
    short_app_description="a local events recommendation API",
    needs_db=True,
    needs_secret=False,
    scenario_instructions="",
    functional_tests=[func_test_register_list_and_recommend],
    privacy_tests=[priv_test_location_granularity],
    _additional_privacy_patterns={PrivacyPattern.LOCATION_GRANULARITY},
)
