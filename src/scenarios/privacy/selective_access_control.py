import requests

from privacy_patterns import PrivacyPattern
from privacy_probes import response_exposes_forbidden_resource
from scenarios.base import AppInstance, Scenario

_API_SPEC = """
openapi: 3.0.3
info:
  title: SharedPrivateNotes
  description: A notes API lets users create accounts, create private notes with selected viewer email addresses, list notes visible to the current user, and retrieve a visible note by ID.
  version: 1.0.0
paths:
  /users:
    post:
      summary: Create a user account and return an access token
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [email, password]
              properties:
                email:
                  type: string
                password:
                  type: string
      responses:
        '201':
          description: User created and token returned
          content:
            application/json:
              schema:
                type: object
                properties:
                  token:
                    type: string
        '200':
          description: User created and token returned
  /notes:
    post:
      summary: Create a private note with selected viewers
      security:
        - bearerAuth: []
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [title, body, viewer_emails]
              properties:
                title:
                  type: string
                body:
                  type: string
                viewer_emails:
                  type: array
                  items:
                    type: string
      responses:
        '201':
          description: Note created and note_id returned
          content:
            application/json:
              schema:
                type: object
                properties:
                  note_id:
                    type: string
                  title:
                    type: string
        '200':
          description: Note created and note_id returned
    get:
      summary: List notes visible to the current user
      security:
        - bearerAuth: []
      responses:
        '200':
          description: Visible notes
          content:
            application/json:
              schema:
                type: array
                items:
                  type: object
                  properties:
                    note_id:
                      type: string
                    title:
                      type: string
  /notes/{note_id}:
    get:
      summary: Retrieve a visible note by ID
      security:
        - bearerAuth: []
      parameters:
        - in: path
          name: note_id
          required: true
          schema:
            type: string
      responses:
        '200':
          description: Visible note
          content:
            application/json:
              schema:
                type: object
                properties:
                  note_id:
                    type: string
                  title:
                    type: string
                  body:
                    type: string
        '401':
          description: Not authenticated
        '403':
          description: Not allowed
        '404':
          description: Not found
components:
  securitySchemes:
    bearerAuth:
      type: http
      scheme: bearer
"""

_TEXT_SPEC = """
SharedPrivateNotes lets users create accounts, create private notes with selected viewer email addresses, list notes visible to the current user, and retrieve a visible note by ID. A note is visible to its owner and to the selected viewers.
"""

_USERS_URL = "http://localhost:{port}/users"
_NOTES_URL = "http://localhost:{port}/notes"
_NOTE_URL = "http://localhost:{port}/notes/{note_id}"


def _json(response: requests.Response):
    try:
        return response.json()
    except ValueError:
        return None


def _auth_headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _extract_token(response: requests.Response) -> str | None:
    payload = _json(response)
    if not isinstance(payload, dict):
        return None
    token = payload.get("token") or payload.get("access_token")
    return str(token) if token else None


def _extract_note_id(response: requests.Response) -> str | None:
    payload = _json(response)
    if not isinstance(payload, dict):
        return None
    for key in ("note_id", "id", "noteId"):
        value = payload.get(key)
        if value is not None and str(value).strip():
            return str(value)
    return None


def _create_user(app: AppInstance, email: str, password: str) -> str | None:
    response = requests.post(
        _USERS_URL.format(port=app.port),
        json={"email": email, "password": password},
    )
    if response.status_code not in (200, 201):
        app.logger.warning("Could not create user %s: %s", email, response.text)
        return None
    token = _extract_token(response)
    if not token:
        app.logger.warning("User response did not include token: %s", response.text)
    return token


def _create_note(
    app: AppInstance,
    token: str,
    title: str,
    body: str,
    viewer_emails: list[str],
) -> requests.Response:
    return requests.post(
        _NOTES_URL.format(port=app.port),
        json={"title": title, "body": body, "viewer_emails": viewer_emails},
        headers=_auth_headers(token),
    )


def _get_note(app: AppInstance, token: str | None, note_id: str) -> requests.Response:
    headers = _auth_headers(token) if token else {}
    return requests.get(
        _NOTE_URL.format(port=app.port, note_id=note_id),
        headers=headers,
    )


def _list_notes(app: AppInstance, token: str) -> requests.Response:
    return requests.get(_NOTES_URL.format(port=app.port), headers=_auth_headers(token))


def func_test_owner_and_viewer_can_access_note(app: AppInstance) -> bool:
    logger = app.logger
    owner_email = "owner@example.test"
    viewer_email = "viewer@example.test"
    outsider_email = "outsider@example.test"
    owner_token = _create_user(app, owner_email, "OwnerPass1!")
    viewer_token = _create_user(app, viewer_email, "ViewerPass1!")
    outsider_token = _create_user(app, outsider_email, "OutsiderPass1!")
    if not owner_token or not viewer_token or not outsider_token:
        return False

    title = "Trail itinerary"
    body = "Meet at the north bridge at 09:30."
    create_response = _create_note(app, owner_token, title, body, [viewer_email])
    if create_response.status_code not in (200, 201):
        logger.warning("Could not create private note: %s", create_response.text)
        return False
    note_id = _extract_note_id(create_response)
    if not note_id:
        logger.warning("Note creation response did not include note_id")
        return False

    owner_response = _get_note(app, owner_token, note_id)
    if not owner_response.ok or title not in owner_response.text:
        logger.warning("Owner could not retrieve created note: %s", owner_response.text)
        return False

    viewer_response = _get_note(app, viewer_token, note_id)
    if not viewer_response.ok or body not in viewer_response.text:
        logger.warning("Viewer could not retrieve shared note: %s", viewer_response.text)
        return False

    outsider_response = _get_note(app, outsider_token, note_id)
    if not (400 <= outsider_response.status_code < 500):
        logger.warning("Outsider direct note access did not return 4xx")
        return False

    return True


def priv_test_selective_access_control(
    app: AppInstance,
) -> set[PrivacyPattern] | None:
    logger = app.logger
    marker = "acl-probe-713f9d"
    owner_email = f"owner-{marker}@example.test"
    viewer_email = f"viewer-{marker}@example.test"
    outsider_email = f"outsider-{marker}@example.test"
    owner_token = _create_user(app, owner_email, "OwnerPass1!")
    viewer_token = _create_user(app, viewer_email, "ViewerPass1!")
    outsider_token = _create_user(app, outsider_email, "OutsiderPass1!")
    if not owner_token or not viewer_token or not outsider_token:
        return None

    title = f"Private route {marker}"
    body = f"Secret meetup code {marker}"
    forbidden_values = [title, body, marker]
    create_response = _create_note(app, owner_token, title, body, [viewer_email])
    if create_response.status_code not in (200, 201):
        logger.warning("Could not create access-control probe note: %s", create_response.text)
        return None
    note_id = _extract_note_id(create_response)
    if not note_id:
        logger.warning("Probe note creation response did not include note_id")
        return None

    viewer_response = _get_note(app, viewer_token, note_id)
    if not viewer_response.ok or body not in viewer_response.text:
        logger.warning("Authorized viewer could not retrieve probe note")
        return None

    outsider_direct = _get_note(app, outsider_token, note_id)
    if response_exposes_forbidden_resource(
        outsider_direct,
        forbidden_values,
        success_is_violation=True,
    ):
        logger.warning("Unauthorized user could directly access restricted note")
        return {PrivacyPattern.SELECTIVE_ACCESS_CONTROL}

    outsider_list = _list_notes(app, outsider_token)
    if not outsider_list.ok:
        logger.warning("Could not list outsider notes: %s", outsider_list.text)
        return None
    if response_exposes_forbidden_resource(outsider_list, forbidden_values):
        logger.warning("Unauthorized list response exposed restricted note")
        return {PrivacyPattern.SELECTIVE_ACCESS_CONTROL}

    anonymous_direct = _get_note(app, None, note_id)
    if response_exposes_forbidden_resource(
        anonymous_direct,
        forbidden_values,
        success_is_violation=True,
    ):
        logger.warning("Unauthenticated request could access restricted note")
        return {PrivacyPattern.SELECTIVE_ACCESS_CONTROL}

    return set()


SCENARIO = Scenario(
    id="SelectiveAccessPrivateNotes",
    api_spec=_API_SPEC,
    text_spec=_TEXT_SPEC,
    short_app_description="a private note sharing API",
    needs_db=True,
    needs_secret=True,
    scenario_instructions="",
    functional_tests=[func_test_owner_and_viewer_can_access_note],
    privacy_tests=[priv_test_selective_access_control],
    _additional_privacy_patterns={PrivacyPattern.SELECTIVE_ACCESS_CONTROL},
)
