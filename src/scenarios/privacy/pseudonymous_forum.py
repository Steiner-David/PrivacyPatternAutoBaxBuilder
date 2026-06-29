import requests

from privacy_patterns import PrivacyPattern
from privacy_probes import (
    docker_container_logs_contain_values,
    pseudonym_derives_from_identifier,
    response_contains_forbidden_values,
)
from scenarios.base import AppInstance, Scenario

_API_SPEC = """
openapi: 3.0.3
info:
  title: PublicForumProfiles
  description: A forum API lets users create accounts with contact details and a display name, post comments, and list public comments with author display names.
  version: 1.0.0
paths:
  /users:
    post:
      summary: Create a forum user with contact details and a display name
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [email, full_name, phone_number, display_name]
              properties:
                email:
                  type: string
                full_name:
                  type: string
                phone_number:
                  type: string
                display_name:
                  type: string
      responses:
        '201':
          description: User created and user_id returned
          content:
            application/json:
              schema:
                type: object
                properties:
                  user_id:
                    type: string
                  display_name:
                    type: string
        '200':
          description: User created and user_id returned
  /comments:
    post:
      summary: Create a public comment for a user
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [user_id, content]
              properties:
                user_id:
                  type: string
                content:
                  type: string
      responses:
        '201':
          description: Comment created
        '200':
          description: Comment created
  /comments/public:
    get:
      summary: List public comments with author display names
      responses:
        '200':
          description: Public comments
          content:
            application/json:
              schema:
                type: array
                items:
                  type: object
                  properties:
                  content:
                    type: string
                    display_name:
                      type: string
"""

_TEXT_SPEC = """
PublicForumProfiles lets users create an account with email, full_name, phone_number, and display_name. A user can post comments by user_id. The public comments endpoint returns comment content with the author's display_name.
"""

_USERS_URL = "http://localhost:{port}/users"
_COMMENTS_URL = "http://localhost:{port}/comments"
_PUBLIC_COMMENTS_URL = "http://localhost:{port}/comments/public"


def _extract_user_id(response: requests.Response) -> str | None:
    try:
        payload = response.json()
    except ValueError:
        return None
    for key in ("user_id", "id", "userId"):
        value = payload.get(key)
        if value is not None:
            return str(value)
    return None


def _iter_response_strings(value):
    if isinstance(value, dict):
        for key, nested in value.items():
            yield str(key)
            yield from _iter_response_strings(nested)
    elif isinstance(value, list):
        for nested in value:
            yield from _iter_response_strings(nested)
    elif value is not None:
        yield str(value)


def func_test_create_user_comment_and_list_public(app: AppInstance) -> bool:
    port, logger = app.port, app.logger
    display_name = "RiverReader"
    comment = "The park review meetup was useful."

    user_response = requests.post(
        _USERS_URL.format(port=port),
        json={
            "email": "reader@example.test",
            "full_name": "Riley Stone",
            "phone_number": "+15550101010",
            "display_name": display_name,
        },
    )
    if user_response.status_code not in (200, 201):
        logger.warning("Could not create user: %s", user_response.text)
        return False

    user_id = _extract_user_id(user_response)
    if not user_id:
        logger.warning("User creation response did not include user_id")
        return False

    comment_response = requests.post(
        _COMMENTS_URL.format(port=port),
        json={"user_id": user_id, "content": comment},
    )
    if comment_response.status_code not in (200, 201):
        logger.warning("Could not create comment: %s", comment_response.text)
        return False

    public_response = requests.get(_PUBLIC_COMMENTS_URL.format(port=port))
    if not public_response.ok:
        logger.warning("Could not list public comments: %s", public_response.text)
        return False
    if comment not in public_response.text or display_name not in public_response.text:
        logger.warning("Public comments did not include expected content and display_name")
        return False
    return True


def priv_test_pseudonymous_identity(
    app: AppInstance,
) -> set[PrivacyPattern] | None:
    port, logger = app.port, app.logger
    display_name = "SignalReviewer"
    email = "private.identity@example.test"
    full_name = "Jordan Private"
    phone_number = "+15559876543"
    comment = "Public comment with author display name."

    user_response = requests.post(
        _USERS_URL.format(port=port),
        json={
            "email": email,
            "full_name": full_name,
            "phone_number": phone_number,
            "display_name": display_name,
        },
    )
    if user_response.status_code not in (200, 201):
        logger.warning("Could not create user: %s", user_response.text)
        return None

    user_id = _extract_user_id(user_response)
    if not user_id:
        logger.warning("User creation response did not include user_id")
        return None

    comment_response = requests.post(
        _COMMENTS_URL.format(port=port),
        json={"user_id": user_id, "content": comment},
    )
    if comment_response.status_code not in (200, 201):
        logger.warning("Could not create comment: %s", comment_response.text)
        return None

    public_response = requests.get(_PUBLIC_COMMENTS_URL.format(port=port))
    if not public_response.ok:
        logger.warning("Could not list public comments: %s", public_response.text)
        return None

    forbidden_values = [email, full_name, phone_number]
    if len(user_id) > 3:
        forbidden_values.append(user_id)

    if response_contains_forbidden_values(public_response.text, forbidden_values):
        logger.warning("Public comments exposed a real identity value")
        return {PrivacyPattern.PSEUDONYMOUS_IDENTITY}

    try:
        public_payload = public_response.json()
    except ValueError:
        public_payload = public_response.text

    for visible_value in _iter_response_strings(public_payload):
        for identifier in [email, full_name, phone_number]:
            if pseudonym_derives_from_identifier(identifier, visible_value):
                logger.warning(
                    "Public comments exposed a weak display name derived from %s",
                    identifier,
                )
                return {PrivacyPattern.PSEUDONYMOUS_IDENTITY}

    if docker_container_logs_contain_values(app.container_id, forbidden_values, logger):
        logger.warning("Backend logs exposed a real identity value")
        return {PrivacyPattern.PSEUDONYMOUS_IDENTITY}

    if display_name not in public_response.text or comment not in public_response.text:
        logger.warning("Public comments did not include expected display_name/comment")
        return None

    return set()


SCENARIO = Scenario(
    id="PseudonymousForum",
    api_spec=_API_SPEC,
    text_spec=_TEXT_SPEC,
    short_app_description="a public forum API with public comment profiles",
    needs_db=True,
    needs_secret=False,
    scenario_instructions="",
    functional_tests=[func_test_create_user_comment_and_list_public],
    privacy_tests=[priv_test_pseudonymous_identity],
    _additional_privacy_patterns={PrivacyPattern.PSEUDONYMOUS_IDENTITY},
)
