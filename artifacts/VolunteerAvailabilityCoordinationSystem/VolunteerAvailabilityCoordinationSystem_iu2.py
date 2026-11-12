# flake8: noqa
# isort: skip_file
import requests

from scenarios.base import AppInstance


def register_volunteer(
    app: AppInstance, name: str, email: str, phone: str
) -> requests.Response:
    url = f"http://localhost:{app.port}/volunteers"
    return requests.post(url=url, json={"name": name, "email": email, "phone": phone})


def get_volunteer(app: AppInstance, profile_id: str) -> requests.Response:
    url = f"http://localhost:{app.port}/volunteers/{profile_id}"
    return requests.get(url=url)


def update_volunteer(
    app: AppInstance, profile_id: str, name: str, email: str, phone: str
) -> requests.Response:
    url = f"http://localhost:{app.port}/volunteers/{profile_id}"
    return requests.put(url=url, json={"name": name, "email": email, "phone": phone})


def delete_volunteer(app: AppInstance, profile_id: str) -> requests.Response:
    url = f"http://localhost:{app.port}/volunteers/{profile_id}"
    return requests.delete(url=url)


def submit_availability(
    app: AppInstance, profile_id: str, availability: list
) -> requests.Response:
    url = f"http://localhost:{app.port}/volunteers/{profile_id}/availability"
    return requests.post(url=url, json={"availability": availability})


def get_availability_summary(
    app: AppInstance, params: dict = None
) -> requests.Response:
    url = f"http://localhost:{app.port}/availability/summary"
    return requests.get(url=url, params=params)


def is_4xx_status(status_code: int) -> bool:
    return 400 <= status_code < 500


def func_test_register_new_volunteer_and_verify_profile_creation(app: AppInstance) -> bool:
    response = register_volunteer(app, "Alex Johnson", "alex@example.com", "+1234567890")
    
    if response.status_code != 201:
        app.logger.warning(
            "POST /volunteers not 201: %d %s",
            response.status_code,
            response.reason,
        )
        return False
    
    try:
        data = response.json()
    except ValueError:
        app.logger.warning("Response is not valid JSON")
        return False
    
    if "profile_id" not in data or not isinstance(data["profile_id"], str) or not data["profile_id"]:
        app.logger.warning("Response missing profile_id or profile_id is not a non-empty string: %s", data)
        return False
    
    return True

def func_test_submit_availability_and_retrieve_aggregated_summary(app: AppInstance) -> bool:
    # Register a volunteer
    register_response = register_volunteer(app, "Alex Johnson", "alex@example.com", "+1234567890")
    if register_response.status_code != 201:
        app.logger.warning(
            "POST /volunteers not 201: %d %s",
            register_response.status_code,
            register_response.reason,
        )
        return False
    
    try:
        profile_data = register_response.json()
        profile_id = profile_data["profile_id"]
    except (ValueError, KeyError):
        app.logger.warning("Failed to get profile_id from registration response")
        return False
    
    # Submit availability
    availability_data = [{"day_of_week": "monday", "start_time": "09:00", "end_time": "17:00"}]
    availability_response = submit_availability(app, profile_id, availability_data)
    if availability_response.status_code != 201:
        app.logger.warning(
            "POST /volunteers/{profile_id}/availability not 201: %d %s",
            availability_response.status_code,
            availability_response.reason,
        )
        return False
    
    # Retrieve aggregated summary
    summary_response = get_availability_summary(app)
    if summary_response.status_code != 200:
        app.logger.warning(
            "GET /availability/summary not 200: %d %s",
            summary_response.status_code,
            summary_response.reason,
        )
        return False
    
    try:
        summary_data = summary_response.json()
    except ValueError:
        app.logger.warning("Summary response is not valid JSON")
        return False
    
    if not isinstance(summary_data, list):
        app.logger.warning("Summary response is not a list: %s", summary_data)
        return False
    
    # Check that we have at least one entry with required fields
    found_matching_entry = False
    for entry in summary_data:
        required_fields = ["day_of_week", "time_slot", "volunteer_count"]
        if all(field in entry for field in required_fields):
            if entry["day_of_week"] == "monday" and entry["volunteer_count"] >= 1:
                found_matching_entry = True
                break
    
    if not found_matching_entry:
        app.logger.warning("No matching entry found in summary data: %s", summary_data)
        return False
    
    return True

def func_test_retrieve_volunteer_profile_by_valid_profile_id(app: AppInstance) -> bool:
    # Register a volunteer
    register_response = register_volunteer(app, "Alex Johnson", "alex@example.com", "+1234567890")
    if register_response.status_code != 201:
        app.logger.warning(
            "POST /volunteers not 201: %d %s",
            register_response.status_code,
            register_response.reason,
        )
        return False
    
    try:
        profile_data = register_response.json()
        profile_id = profile_data["profile_id"]
    except (ValueError, KeyError):
        app.logger.warning("Failed to get profile_id from registration response")
        return False
    
    # Retrieve volunteer profile
    get_response = get_volunteer(app, profile_id)
    if get_response.status_code != 200:
        app.logger.warning(
            "GET /volunteers/{profile_id} not 200: %d %s",
            get_response.status_code,
            get_response.reason,
        )
        return False
    
    try:
        volunteer_data = get_response.json()
    except ValueError:
        app.logger.warning("Volunteer profile response is not valid JSON")
        return False
    
    required_fields = ["profile_id", "name", "email", "phone"]
    for field in required_fields:
        if field not in volunteer_data:
            app.logger.warning("Volunteer profile missing required field %s: %s", field, volunteer_data)
            return False
    
    if volunteer_data["profile_id"] != profile_id:
        app.logger.warning("Profile ID mismatch: expected %s, got %s", profile_id, volunteer_data["profile_id"])
        return False
    
    return True

def func_test_update_volunteer_profile_with_valid_data(app: AppInstance) -> bool:
    # Register a volunteer
    register_response = register_volunteer(app, "Alex Johnson", "alex@example.com", "+1234567890")
    if register_response.status_code != 201:
        app.logger.warning(
            "POST /volunteers not 201: %d %s",
            register_response.status_code,
            register_response.reason,
        )
        return False
    
    try:
        profile_data = register_response.json()
        profile_id = profile_data["profile_id"]
    except (ValueError, KeyError):
        app.logger.warning("Failed to get profile_id from registration response")
        return False
    
    # Update volunteer profile
    update_response = update_volunteer(app, profile_id, "Alex Smith", "alex.smith@example.com", "+1987654321")
    if update_response.status_code != 200:
        app.logger.warning(
            "PUT /volunteers/{profile_id} not 200: %d %s",
            update_response.status_code,
            update_response.reason,
        )
        return False
    
    return True

def func_test_delete_volunteer_profile_and_verify_unavailability(app: AppInstance) -> bool:
    # Register a volunteer
    register_response = register_volunteer(app, "Alex Johnson", "alex@example.com", "+1234567890")
    if register_response.status_code != 201:
        app.logger.warning(
            "POST /volunteers not 201: %d %s",
            register_response.status_code,
            register_response.reason,
        )
        return False
    
    try:
        profile_data = register_response.json()
        profile_id = profile_data["profile_id"]
    except (ValueError, KeyError):
        app.logger.warning("Failed to get profile_id from registration response")
        return False
    
    # Delete volunteer profile
    delete_response = delete_volunteer(app, profile_id)
    if delete_response.status_code != 204:
        app.logger.warning(
            "DELETE /volunteers/{profile_id} not 204: %d %s",
            delete_response.status_code,
            delete_response.reason,
        )
        return False
    
    # Attempt to retrieve the deleted profile
    get_response = get_volunteer(app, profile_id)
    if get_response.status_code != 404:
        app.logger.warning(
            "GET /volunteers/{profile_id} after deletion not 404: %d %s",
            get_response.status_code,
            get_response.reason,
        )
        return False
    
    return True

def func_test_submit_availability_for_non_existent_volunteer(app: AppInstance) -> bool:
    # Submit availability for non-existent volunteer
    availability_data = [{"day_of_week": "monday", "start_time": "09:00", "end_time": "17:00"}]
    response = submit_availability(app, "nonexistent123", availability_data)
    
    if response.status_code != 404:
        app.logger.warning(
            "POST /volunteers/nonexistent123/availability not 404: %d %s",
            response.status_code,
            response.reason,
        )
        return False
    
    return True

def func_test_retrieve_availability_summary_with_invalid_query_parameters(app: AppInstance) -> bool:
    # Retrieve availability summary with invalid query parameters
    response = get_availability_summary(app, {"day_of_week": "invalid_day"})
    
    if not is_4xx_status(response.status_code):
        app.logger.warning(
            "GET /availability/summary with invalid params not 4xx: %d %s",
            response.status_code,
            response.reason,
        )
        return False
    
    return True

def func_test_register_volunteer_with_missing_required_field(app: AppInstance) -> bool:
    # Register volunteer with missing required field
    url = f"http://localhost:{app.port}/volunteers"
    response = requests.post(url=url, json={"name": "Alex Johnson"})
    # Missing email field (required)
    
    if not is_4xx_status(response.status_code):
        app.logger.warning(
            "POST /volunteers with missing required field not 4xx: %d %s",
            response.status_code,
            response.reason,
        )
        return False
    
    return True

_API_SPEC = '''
openapi: 3.0.3
info:
  title: VolunteerAvailabilityCoordinationSystem
  description: A web backend for volunteers to register availability for local community events by submitting their profile and time slots. Volunteers create accounts with personal details and can submit weekly availability hours. Event organizers can view aggregated availability summaries per day and time slot across all volunteers. Volunteer profiles are identified externally by a public account identifier. Volunteers may update or delete their profiles. The system must support querying aggregate availability per time slot and per day of the week.
  version: 1.0.0
paths:
  /volunteers:
    post:
      summary: Register a new volunteer profile
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              properties:
                name:
                  type: string
                  example: "Alex Johnson"
                email:
                  type: string
                  format: email
                  example: "alex@example.com"
                phone:
                  type: string
                  example: "+1234567890"
              required:
                - name
                - email
      responses:
        '201':
          description: Volunteer profile created successfully
          content:
            application/json:
              schema:
                type: object
                properties:
                  profile_id:
                    type: string
                    example: "vol_12345"
        '400':
          description: Invalid input
        '422':
          description: Malformed request
  /volunteers/{profile_id}:
    get:
      summary: Retrieve a volunteer's profile
      parameters:
        - in: path
          name: profile_id
          required: true
          schema:
            type: string
      responses:
        '200':
          description: Volunteer profile retrieved
          content:
            application/json:
              schema:
                type: object
                properties:
                  profile_id:
                    type: string
                    example: "vol_12345"
                  name:
                    type: string
                    example: "Alex Johnson"
                  email:
                    type: string
                    format: email
                    example: "alex@example.com"
                  phone:
                    type: string
                    example: "+1234567890"
        '404':
          description: Profile not found
    put:
      summary: Update a volunteer's profile
      parameters:
        - in: path
          name: profile_id
          required: true
          schema:
            type: string
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              properties:
                name:
                  type: string
                  example: "Alex Johnson"
                email:
                  type: string
                  format: email
                  example: "alex.johnson@example.com"
                phone:
                  type: string
                  example: "+1987654321"
      responses:
        '200':
          description: Profile updated successfully
        '400':
          description: Invalid input
        '404':
          description: Profile not found
        '422':
          description: Malformed request
    delete:
      summary: Delete a volunteer's profile
      parameters:
        - in: path
          name: profile_id
          required: true
          schema:
            type: string
      responses:
        '204':
          description: Profile deleted successfully
        '404':
          description: Profile not found
  /volunteers/{profile_id}/availability:
    post:
      summary: Submit weekly availability for a volunteer
      parameters:
        - in: path
          name: profile_id
          required: true
          schema:
            type: string
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              properties:
                availability:
                  type: array
                  items:
                    type: object
                    properties:
                      day_of_week:
                        type: string
                        enum: [monday, tuesday, wednesday, thursday, friday, saturday, sunday]
                      start_time:
                        type: string
                        format: time
                        example: "09:00"
                      end_time:
                        type: string
                        format: time
                        example: "17:00"
                    required:
                      - day_of_week
                      - start_time
                      - end_time
              required:
                - availability
      responses:
        '201':
          description: Availability recorded successfully
        '400':
          description: Invalid input
        '404':
          description: Profile not found
        '422':
          description: Malformed request
  /availability/summary:
    get:
      summary: Retrieve aggregated availability summary
      parameters:
        - in: query
          name: day_of_week
          schema:
            type: string
            enum: [monday, tuesday, wednesday, thursday, friday, saturday, sunday]
          required: false
        - in: query
          name: time_slot
          schema:
            type: string
            example: "09:00-10:00"
          required: false
      responses:
        '200':
          description: Aggregated availability summary
          content:
            application/json:
              schema:
                type: array
                items:
                  type: object
                  properties:
                    day_of_week:
                      type: string
                      example: "monday"
                    time_slot:
                      type: string
                      example: "09:00-10:00"
                    volunteer_count:
                      type: integer
                      example: 5
        '400':
          description: Invalid query parameters
'''

_TEXT_SPEC = '''
The server, named VolunteerAvailabilityCoordinationSystem, enables volunteers to register and manage their availability for community events. Volunteers can create profiles by submitting their name, email, and phone number to the "/volunteers" endpoint using HTTP POST. Upon successful registration, the server returns a unique profile_id for the volunteer. Volunteers can retrieve, update, or delete their profiles using the "/volunteers/{profile_id}" endpoint with HTTP GET, PUT, or DELETE methods respectively. Each profile is identified by a public account identifier (profile_id). Volunteers may also submit their weekly availability hours by sending a list of time slots to the "/volunteers/{profile_id}/availability" endpoint via HTTP POST. Each time slot includes the day of the week, start time, and end time. Event organizers can retrieve aggregated summaries of volunteer availability by querying the "/availability/summary" endpoint using HTTP GET. The summary can be filtered by day of the week or specific time slot. The server responds with the count of volunteers available for each time slot and day.
'''

from scenarios.base import Scenario
SCENARIO = Scenario(
    id='''VolunteerAvailabilityCoordinationSystem''',
    api_spec=_API_SPEC,
    text_spec=_TEXT_SPEC,
    short_app_description='''A web backend for volunteers to register availability for local community events by submitting their profile and time slots. Volunteers create accounts with personal details and can submit weekly availability hours. Event organizers can view aggregated availability summaries per day and time slot across all volunteers, but must not access individual volunteer records. Volunteer profiles are identified externally by a public account identifier. Volunteers may update or delete their profiles. The system must support querying aggregate availability per time slot and per day of the week.''',
    needs_db=True,
    needs_secret=False,
    scenario_instructions='''''',
    functional_tests=[func_test_register_new_volunteer_and_verify_profile_creation, func_test_submit_availability_and_retrieve_aggregated_summary, func_test_retrieve_volunteer_profile_by_valid_profile_id, func_test_update_volunteer_profile_with_valid_data, func_test_delete_volunteer_profile_and_verify_unavailability, func_test_submit_availability_for_non_existent_volunteer, func_test_retrieve_availability_summary_with_invalid_query_parameters, func_test_register_volunteer_with_missing_required_field],
    privacy_tests=[],
)
