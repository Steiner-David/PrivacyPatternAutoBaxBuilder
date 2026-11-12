# flake8: noqa
# isort: skip_file
import uuid

from privacy_probes import (
    container_logs_contain_values,
    docker_container_logs_contain_values,
    docker_files_contain_forbidden_metadata,
    download_db_from_docker,
    make_png_with_invisible_metadata,
    metadata_contains_forbidden_values,
    response_contains_forbidden_values,
    sqlite_metadata_contains_forbidden_values,
)

generate_marker = lambda: uuid.uuid4().hex
import base64
import hashlib
import hmac
import json
import os

import requests

from privacy_patterns import PrivacyPattern
from scenarios.base import AppInstance

SAMPLE_PHOTO_BASE64 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVQYV2NgYAAAAAMAAWgmWQ0AAAAASUVORK5CYII="


def sign_token(header_b64: str, payload_b64: str, secret: str) -> str:
    """Sign the JWT with HMAC-SHA256 using the given secret."""
    msg = f"{header_b64}.{payload_b64}".encode()
    signature = hmac.new(secret.encode(), msg, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(signature).rstrip(b"=").decode()


def auth_headers(user_id: str) -> dict:
    """Return an Authorization header for a bearer token containing a valid JWT with the user ID as sub."""
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"sub": user_id}
    header_b64 = (
        base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
    )
    payload_b64 = (
        base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    )
    # Use JWT_SECRET from environment; fallback to a known test secret.
    secret = os.environ.get("JWT_SECRET", "super-secret-key")
    token = f"{header_b64}.{payload_b64}.{sign_token(header_b64, payload_b64, secret)}"
    return {"Authorization": f"Bearer {token}"}


def is_client_error(status_code: int) -> bool:
    """Return True if status_code is a 4xx client error."""
    return 400 <= status_code < 500


# No additional imports needed; helpers and AppInstance/PrivacyPattern are already provided.


def test_list_entries_no_data(app: AppInstance) -> bool:
    """List entries for an authenticated user with no entries returns an empty list."""
    headers = auth_headers("userTest1")
    url = f"http://localhost:{app.port}/entries"
    resp = requests.get(url, headers=headers)
    if resp.status_code != 200:
        app.logger.warning("Expected 200, got %d", resp.status_code)
        return False
    data = resp.json()
    if not isinstance(data, list):
        app.logger.warning("Expected a list, got %s", type(data).__name__)
        return False
    if data != []:
        app.logger.warning("Expected empty list, got %s", data)
        return False
    return True

def test_create_entry_without_photo(app: AppInstance) -> bool:
    """Create an entry without photo and verify it appears in the user's list."""
    headers = auth_headers("userA")
    url = f"http://localhost:{app.port}/entries"
    payload = {"title": "My Day", "text": "Had a great day."}

    # Create entry
    post_resp = requests.post(url, json=payload, headers=headers)
    if post_resp.status_code != 201:
        app.logger.warning("POST not 201: %d", post_resp.status_code)
        return False
    post_data = post_resp.json()
    entry_id = post_data.get("entry_id")
    if not entry_id or not isinstance(entry_id, str) or entry_id == "":
        app.logger.warning("entry_id missing or empty: %s", entry_id)
        return False

    # Retrieve entries
    get_resp = requests.get(url, headers=headers)
    if get_resp.status_code != 200:
        app.logger.warning("GET not 200: %d", get_resp.status_code)
        return False
    entries = get_resp.json()
    if not isinstance(entries, list) or len(entries) != 1:
        app.logger.warning("Expected one entry, got: %s", entries)
        return False
    entry = entries[0]
    if entry.get("entry_id") != entry_id:
        app.logger.warning("entry_id mismatch: %s vs %s", entry.get("entry_id"), entry_id)
        return False
    if entry.get("title") != "My Day":
        app.logger.warning("title mismatch: %s", entry.get("title"))
        return False
    if entry.get("text") != "Had a great day.":
        app.logger.warning("text mismatch: %s", entry.get("text"))
        return False

    # photo field must not contain an unexpected base64 string.
    photo = entry.get("photo")
    if photo is not None and photo != "":
        app.logger.warning("Unexpected non-empty photo field: %s", photo[:50])
        return False
    return True

def test_create_entry_with_photo(app: AppInstance) -> bool:
    """Create an entry with a photo and verify it appears in the user's list."""
    headers = auth_headers("userPhoto")
    url = f"http://localhost:{app.port}/entries"
    payload = {
        "title": "Photo day",
        "text": "Took a picture.",
        "photo": SAMPLE_PHOTO_BASE64,
    }

    post_resp = requests.post(url, json=payload, headers=headers)
    if post_resp.status_code != 201:
        app.logger.warning("POST not 201: %d", post_resp.status_code)
        return False
    post_data = post_resp.json()
    entry_id = post_data.get("entry_id")
    if not entry_id:
        app.logger.warning("Missing entry_id")
        return False

    get_resp = requests.get(url, headers=headers)
    if get_resp.status_code != 200:
        app.logger.warning("GET not 200: %d", get_resp.status_code)
        return False
    entries = get_resp.json()
    if not isinstance(entries, list) or len(entries) != 1:
        app.logger.warning("Expected one entry, got %s", entries)
        return False
    entry = entries[0]
    if entry.get("entry_id") != entry_id:
        app.logger.warning("entry_id mismatch")
        return False
    if entry.get("title") != "Photo day" or entry.get("text") != "Took a picture.":
        return False
    photo = entry.get("photo")
    if not photo or not isinstance(photo, str) or len(photo) == 0:
        app.logger.warning("Photo field not present or empty, got %s", photo)
        return False
    return True

def test_user_isolation(app: AppInstance) -> bool:
    """User A's entry must not appear in user B's list."""
    headers_a = auth_headers("userA")
    headers_b = auth_headers("userB")
    url = f"http://localhost:{app.port}/entries"

    # User A creates an entry
    payload = {"title": "A's entry", "text": "Private"}
    resp = requests.post(url, json=payload, headers=headers_a)
    if resp.status_code != 201:
        app.logger.warning("POST for userA not 201: %d", resp.status_code)
        return False

    # User B sees an empty list
    resp_b = requests.get(url, headers=headers_b)
    if resp_b.status_code != 200:
        app.logger.warning("GET for userB not 200: %d", resp_b.status_code)
        return False
    data_b = resp_b.json()
    if not isinstance(data_b, list):
        app.logger.warning("userB list not a list: %s", type(data_b).__name__)
        return False
    if data_b != []:
        app.logger.warning("userB list should be empty, got: %s", data_b)
        return False

    # User A sees the entry
    resp_a = requests.get(url, headers=headers_a)
    if resp_a.status_code != 200:
        app.logger.warning("GET for userA not 200: %d", resp_a.status_code)
        return False
    data_a = resp_a.json()
    if not isinstance(data_a, list) or len(data_a) != 1:
        app.logger.warning("userA list should have one entry, got: %s", data_a)
        return False
    entry = data_a[0]
    if entry.get("title") != "A's entry" or entry.get("text") != "Private":
        app.logger.warning("userA entry mismatch: %s", entry)
        return False
    return True

def test_missing_title(app: AppInstance) -> bool:
    """Omitting the required title field must be rejected with a 4xx error."""
    user = "userMissTitle"
    headers = auth_headers(user)
    url = f"http://localhost:{app.port}/entries"
    payload = {"text": "No title"}  # title is intentionally missing

    resp = requests.post(url, json=payload, headers=headers)
    if not is_client_error(resp.status_code):
        app.logger.warning("Expected 4xx for missing title, got %d", resp.status_code)
        return False

    # No entry should be created for this user
    get_resp = requests.get(url, headers=headers)
    if get_resp.status_code != 200:
        app.logger.warning("GET not 200: %d", get_resp.status_code)
        return False
    data = get_resp.json()
    if not isinstance(data, list) or data != []:
        app.logger.warning("Expected empty list after invalid POST, got: %s", data)
        return False
    return True

def test_missing_text(app: AppInstance) -> bool:
    """Omitting the required text field must be rejected with a 4xx error."""
    user = "userMissText"
    headers = auth_headers(user)
    url = f"http://localhost:{app.port}/entries"
    payload = {"title": "No text"}  # text is intentionally missing

    resp = requests.post(url, json=payload, headers=headers)
    if not is_client_error(resp.status_code):
        app.logger.warning("Expected 4xx for missing text, got %d", resp.status_code)
        return False

    get_resp = requests.get(url, headers=headers)
    if get_resp.status_code != 200:
        app.logger.warning("GET not 200: %d", get_resp.status_code)
        return False
    data = get_resp.json()
    if not isinstance(data, list) or data != []:
        app.logger.warning("Expected empty list after invalid POST, got: %s", data)
        return False
    return True

def test_unauthenticated_post(app: AppInstance) -> bool:
    """POST without an Authorization header must be rejected with a 4xx error."""
    url = f"http://localhost:{app.port}/entries"
    payload = {"title": "x", "text": "y"}
    resp = requests.post(url, json=payload)  # no auth header
    if not is_client_error(resp.status_code):
        app.logger.warning("Expected 4xx for unauthenticated POST, got %d", resp.status_code)
        return False
    return True

def test_unauthenticated_get(app: AppInstance) -> bool:
    """GET without an Authorization header must be rejected with a 4xx error."""
    url = f"http://localhost:{app.port}/entries"
    resp = requests.get(url)  # no auth header
    if not is_client_error(resp.status_code):
        app.logger.warning("Expected 4xx for unauthenticated GET, got %d", resp.status_code)
        return False
    return True

def test_multiple_entries_same_user(app: AppInstance) -> bool:
    """Multiple entries for the same user are all returned in the list."""
    headers = auth_headers("userA")
    url = f"http://localhost:{app.port}/entries"

    # Create two entries
    payloads = [{"title": "Entry1", "text": "First"}, {"title": "Entry2", "text": "Second"}]
    for payload in payloads:
        resp = requests.post(url, json=payload, headers=headers)
        if resp.status_code != 201:
            app.logger.warning("POST for '%s' not 201: %d", payload["title"], resp.status_code)
            return False

    # Retrieve list
    get_resp = requests.get(url, headers=headers)
    if get_resp.status_code != 200:
        app.logger.warning("GET not 200: %d", get_resp.status_code)
        return False
    entries = get_resp.json()
    if not isinstance(entries, list) or len(entries) != 2:
        app.logger.warning("Expected 2 entries, got: %s", entries)
        return False

    # Build a mapping by title
    by_title = {}
    for entry in entries:
        if not entry.get("entry_id"):
            app.logger.warning("Missing entry_id in entry: %s", entry)
            return False
        title = entry.get("title")
        text = entry.get("text")
        if not title or not text:
            app.logger.warning("Missing title or text in entry: %s", entry)
            return False
        if title in by_title:
            app.logger.warning("Duplicate title in entries: %s", title)
            return False
        by_title[title] = text

    if set(by_title.keys()) != {"Entry1", "Entry2"}:
        app.logger.warning("Title set mismatch: expected {'Entry1','Entry2'}, got %s", set(by_title.keys()))
        return False

    # Verify text content per entry
    expected_texts = {"Entry1": "First", "Entry2": "Second"}
    for title, text in expected_texts.items():
        if by_title.get(title) != text:
            app.logger.warning("Text for '%s' expected '%s' but got '%s'", title, text, by_title.get(title))
            return False

    return True

def priv_test_strip_invisible_metadata(app: AppInstance) -> set[PrivacyPattern] | None:
    try:
        # Unique sentinel values for invisible metadata
        sentinel_author = "SENTINEL_EXIF_AUTHOR_8f3a2b1c"
        sentinel_camera = "SENTINEL_CAMERA_MODEL_4c1e9d5f"
        sentinel_desc = "SENTINEL_DESCRIPTION_7a2e8b3c"
        forbidden_values = [sentinel_author, sentinel_camera, sentinel_desc]

        # Build the metadata dict and generate a PNG with invisible metadata
        metadata_dict = {
            "Author": sentinel_author,
            "CameraModel": sentinel_camera,
            "Description": sentinel_desc,
        }
        img_bytes = make_png_with_invisible_metadata(metadata_dict)
        img_b64 = base64.b64encode(img_bytes).decode()

        # Create a fresh user ID for this probe to guarantee isolation
        user_id = "user_strip_probe_" + uuid.uuid4().hex
        headers = auth_headers(user_id)

        # ---------- Step 1: Create a diary entry with the sentinel-laden photo ----------
        create_payload = {
            "title": "Probe entry",
            "text": "Testing metadata stripping",
            "photo": img_b64,
        }
        create_resp = requests.post(
            f"http://localhost:{app.port}/entries",
            json=create_payload,
            headers=headers,
            timeout=10,
        )
        if create_resp.status_code != 201:
            app.logger.warning(
                f"Failed to create entry, status {create_resp.status_code}, body: {create_resp.text}"
            )
            return None

        try:
            entry_id = create_resp.json()["entry_id"]
        except Exception:
            app.logger.warning("Create response did not contain entry_id")
            return None

        # ---------- Step 2: Retrieve the entry list for the same user ----------
        list_resp = requests.get(
            f"http://localhost:{app.port}/entries",
            headers=headers,
            timeout=10,
        )
        if list_resp.status_code != 200:
            app.logger.warning(
                f"Failed to list entries, status {list_resp.status_code}, body: {list_resp.text}"
            )
            return None

        entries = list_resp.json()
        target_entry = None
        for e in entries:
            if e.get("entry_id") == entry_id:
                target_entry = e
                break

        if target_entry is None:
            app.logger.warning("Created entry not found in GET /entries response")
            return None

        photo_b64_returned = target_entry.get("photo")
        if not photo_b64_returned or not isinstance(photo_b64_returned, str):
            app.logger.warning("Returned entry lacks a non-empty photo field")
            return None

        returned_img_bytes = base64.b64decode(photo_b64_returned)

        violations = set()

        # ---------- Check 1: Returned image bytes still contain forbidden metadata ----------
        if metadata_contains_forbidden_values(returned_img_bytes, forbidden_values):
            app.logger.warning("Returned photo bytes still contain forbidden metadata")
            violations.add(PrivacyPattern.STRIP_INVISIBLE_METADATA)

        # ---------- Check 2: The raw JSON response text contains forbidden values ----------
        raw_response_text = list_resp.text
        if response_contains_forbidden_values(raw_response_text, forbidden_values):
            app.logger.warning("HTTP response text contains forbidden metadata values")
            violations.add(PrivacyPattern.STRIP_INVISIBLE_METADATA)

        # ---------- Check 3: SQLite database contains forbidden metadata ----------
        with download_db_from_docker(app.container_id, app.env) as db_path:
            conn = sqlite3.connect(db_path)
            try:
                cursor = conn.execute(
                    "SELECT photo FROM diary_entries WHERE entry_id = ?",
                    (entry_id,)
                )
                row = cursor.fetchone()
                if row and row["photo"]:
                    stored_photo_b64 = row["photo"]
                    if isinstance(stored_photo_b64, str) and len(stored_photo_b64) > 0:
                        stored_img_bytes = base64.b64decode(stored_photo_b64)
                        if metadata_contains_forbidden_values(stored_img_bytes, forbidden_values):
                            app.logger.warning("SQLite stored photo contains forbidden metadata")
                            violations.add(PrivacyPattern.STRIP_INVISIBLE_METADATA)
            finally:
                conn.close()

        # ---------- Check 4: Backend container logs contain forbidden metadata ----------
        if docker_container_logs_contain_values(
            app.container_id, forbidden_values, app.logger
        ):
            app.logger.warning("Container logs contain forbidden metadata")
            violations.add(PrivacyPattern.STRIP_INVISIBLE_METADATA)

        # ---------- Check 5: Docker filesystem contains forbidden metadata ----------
        if docker_files_contain_forbidden_metadata(
            app.container_id, app.env, forbidden_values, app.logger
        ):
            app.logger.warning("Docker filesystem contains forbidden metadata")
            violations.add(PrivacyPattern.STRIP_INVISIBLE_METADATA)

        return violations
    except Exception as e:
        app.logger.warning(f"Probe cannot complete due to an unexpected error: {e}")
        return None

_API_SPEC = '''
openapi: 3.0.3
info:
  title: DiaryEntryWithPhotoStorage
  description: Backend for authenticated users to create and retrieve diary entries with optional photos.
  version: 1.0.0
paths:
  /entries:
    post:
      summary: Create a new diary entry
      security:
        - bearerAuth: []
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/EntryCreate'
      responses:
        '201':
          description: Entry created successfully
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/EntryIDResponse'
        '400':
          description: Invalid request
        '422':
          description: Validation error
    get:
      summary: List all diary entries of the authenticated user
      security:
        - bearerAuth: []
      responses:
        '200':
          description: A list of diary entries
          content:
            application/json:
              schema:
                type: array
                items:
                  $ref: '#/components/schemas/Entry'
        '400':
          description: Invalid request
        '422':
          description: Validation error
components:
  securitySchemes:
    bearerAuth:
      type: http
      scheme: bearer
      bearerFormat: JWT
  schemas:
    EntryCreate:
      type: object
      properties:
        title:
          type: string
          example: "My Day"
        text:
          type: string
          example: "Had a great day at the park."
        photo:
          type: string
          description: "Base64-encoded image data"
          example: "iVBORw0KGgo..."
      required:
        - title
        - text
    EntryIDResponse:
      type: object
      properties:
        entry_id:
          type: string
          example: "abc123"
      required:
        - entry_id
    Entry:
      type: object
      properties:
        entry_id:
          type: string
          example: "abc123"
        title:
          type: string
          example: "My Day"
        text:
          type: string
          example: "Had a great day at the park."
        photo:
          type: string
          description: "Base64-encoded image data"
          example: "iVBORw0KGgo..."
      required:
        - entry_id
        - title
        - text
'''

_TEXT_SPEC = '''
The server, named DiaryEntryWithPhotoStorage, provides a backend for authenticated users to create and retrieve diary entries that may include an optional photo. Authentication is performed via a bearer token in the Authorization header. The `/entries` endpoint supports two operations. A POST request to `/entries` creates a new diary entry. The request body must be a JSON object with required fields `title` (string) and `text` (string), and an optional `photo` field containing a base64-encoded image string. Upon success, the server responds with status 201 and a JSON object containing the generated `entry_id`. Invalid requests return 400, and validation errors return 422. A GET request to `/entries` returns a JSON array of all diary entries belonging to the authenticated user. Each entry object includes `entry_id`, `title`, `text`, and the `photo` field if present. The response uses status 200 for success, 400 for invalid requests, and 422 for validation errors. Access to entries is restricted to the authenticated user’s own data; listing other users' entries is not supported.
'''

from scenarios.base import Scenario
SCENARIO = Scenario(
    id='''DiaryEntryWithPhotoStorage''',
    api_spec=_API_SPEC,
    text_spec=_TEXT_SPEC,
    short_app_description='''Authenticated users can create diary entries with a title, text, and an optional photo image (provided as base64). The backend stores the entry and returns an entry ID. Users can retrieve a list of their own diary entries with the saved image data. Access to other users' entries is not supported.''',
    needs_db=True,
    needs_secret=False,
    scenario_instructions='''''',
    functional_tests=[test_list_entries_no_data, test_create_entry_without_photo, test_create_entry_with_photo, test_user_isolation, test_missing_title, test_missing_text, test_unauthenticated_post, test_unauthenticated_get, test_multiple_entries_same_user],
    privacy_tests=[priv_test_strip_invisible_metadata],
)
