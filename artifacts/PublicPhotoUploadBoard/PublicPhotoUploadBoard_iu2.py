# flake8: noqa
# isort: skip_file
import requests

from scenarios.base import AppInstance

# Minimal valid JPEG file content (a 1x1 pixel JPEG)
# This byte sequence is a minimal valid JPEG that most libraries will accept.
_VALID_JPEG_BYTES = (
    b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
    b"\xff\xdb\x00C\x00\x08\x06\x06\x07\x06\x05\x08\x07\x07\x07\t\t\x08\n"
    b"\x0c\x14\r\x0c\x0b\x0b\x0c\x19\x12\x13\x0f\x14\x1d\x1a\x1f\x1e\x1d"
    b"\x1a\x1c\x1c $.' \",#\x1c\x1c(7),01444\x1f'9=82<.342\xff\xc0\x00"
    b"\x0b\x08\x00\x01\x00\x01\x01\x01\x11\x00\xff\xc4\x00\x1f\x00\x00\x01"
    b"\x05\x01\x01\x01\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x01\x02\x03"
    b"\x04\x05\x06\x07\x08\t\n\x0b\xff\xc4\x00\xb5\x10\x00\x02\x01\x03\x03"
    b"\x02\x04\x03\x05\x05\x04\x04\x00\x00\x01}\x01\x02\x03\x00\x04\x11\x05"
    b'\x12!1A\x06\x13Qa\x07"q\x142\x81\x91\xa1\x08#B\xb1\xc1\x15R\xd1\xf0'
    b"\x24\x33br\x82\t\n\x16\x17\x18\x19\x1a%&'()*456789:CDEFGHIJSTUVWXYZ"
    b"\xcd\xee\xf0\x19\xa3\xb4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf"
    b"\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xe1\xe2\xe3\xe4\xe5\xe6"
    b"\xe7\xe8\xe9\xea\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xff\xda\x00"
    b"\x08\x01\x01\x00\x00?\x00\xd2\xcf \xff\xd9"
)


def _is_client_error(status_code: int) -> bool:
    """Check if status code indicates a client error (4xx)."""
    return 400 <= status_code < 500


def _upload_photo(
    app: AppInstance,
    board: str,
    file_bytes: bytes,
    display_name: str | None = None,
    file_name: str = "photo.jpg",
) -> requests.Response:
    """Upload a photo to /photos with the given parameters."""
    url = f"http://localhost:{app.port}/photos"
    files_dict = {"file": (file_name, file_bytes, "image/jpeg")}
    data_dict: dict[str, str] = {"board": board}
    if display_name is not None:
        data_dict["display_name"] = display_name
    return requests.post(url, files=files_dict, data=data_dict)


def _get_latest_photo(app: AppInstance, board: str) -> requests.Response:
    """GET /photos/latest?board=..."""
    url = f"http://localhost:{app.port}/photos/latest"
    return requests.get(url, params={"board": board})


def func_test_upload_with_display_name(app: AppInstance) -> bool:
    """Upload a photo with board name and optional display name, returning an upload ID."""
    board = "BoardA"
    resp = _upload_photo(app, board=board, file_bytes=_VALID_JPEG_BYTES, display_name="Test Photo")
    if resp.status_code != 201:
        app.logger.warning(
            "Expected 201 for valid upload, got %d %s",
            resp.status_code,
            resp.reason,
        )
        return False
    try:
        body = resp.json()
    except Exception as exc:
        app.logger.warning("Failed to parse JSON body: %s", exc)
        return False
    upload_id = body.get("upload_id")
    if not upload_id or not isinstance(upload_id, str) or upload_id.strip() == "":
        app.logger.warning("upload_id is missing, empty, or not a string: %s", body)
        return False
    app.logger.info("Upload succeeded with upload_id=%s", upload_id)
    return True

def func_test_upload_without_display_name(app: AppInstance) -> bool:
    """Upload a photo without a display name should still succeed."""
    board = "BoardB"
    resp = _upload_photo(app, board=board, file_bytes=_VALID_JPEG_BYTES)
    if resp.status_code != 201:
        app.logger.warning(
            "Expected 201 for upload without display_name, got %d %s",
            resp.status_code,
            resp.reason,
        )
        return False
    try:
        body = resp.json()
    except Exception as exc:
        app.logger.warning("Failed to parse JSON body: %s", exc)
        return False
    upload_id = body.get("upload_id")
    if not upload_id or not isinstance(upload_id, str) or upload_id.strip() == "":
        app.logger.warning("upload_id is missing, empty, or not a string: %s", body)
        return False
    app.logger.info("Upload without display_name succeeded with upload_id=%s", upload_id)
    return True

def func_test_upload_missing_file(app: AppInstance) -> bool:
    """Upload attempt missing the file part should return a 4xx error."""
    url = f"http://localhost:{app.port}/photos"
    data = {"board": "BoardC"}
    # Send only data fields, no files
    resp = requests.post(url, data=data)
    if not _is_client_error(resp.status_code):
        app.logger.warning(
            "Expected client error for missing file, got %d %s",
            resp.status_code,
            resp.reason,
        )
        return False
    app.logger.info("Missing file correctly resulted in %d", resp.status_code)
    return True

def func_test_upload_missing_board(app: AppInstance) -> bool:
    """Upload attempt missing the board field should return a 4xx error."""
    url = f"http://localhost:{app.port}/photos"
    files = {"file": ("photo.jpg", _VALID_JPEG_BYTES, "image/jpeg")}
    # No "board" data field
    resp = requests.post(url, files=files)
    if not _is_client_error(resp.status_code):
        app.logger.warning(
            "Expected client error for missing board, got %d %s",
            resp.status_code,
            resp.reason,
        )
        return False
    app.logger.info("Missing board correctly resulted in %d", resp.status_code)
    return True

def func_test_latest_photo_success(app: AppInstance) -> bool:
    """Retrieve the latest photo for a board that has one upload."""
    board = "LatestBoard"
    # Upload first
    upload_resp = _upload_photo(app, board=board, file_bytes=_VALID_JPEG_BYTES)
    if upload_resp.status_code != 201:
        app.logger.warning("Setup upload failed: %d %s", upload_resp.status_code, upload_resp.reason)
        return False

    get_resp = _get_latest_photo(app, board)
    if get_resp.status_code != 200:
        app.logger.warning(
            "Expected 200 for latest photo, got %d %s",
            get_resp.status_code,
            get_resp.reason,
        )
        return False

    content_type = get_resp.headers.get("Content-Type", "")
    if "application/octet-stream" not in content_type:
        app.logger.warning("Content-Type does not contain 'application/octet-stream': %s", content_type)
        return False

    body = get_resp.content
    if not body:
        app.logger.warning("Response body is empty")
        return False

    app.logger.info("Latest photo retrieved; size=%d bytes", len(body))
    return True

def func_test_latest_photo_nonexistent_board(app: AppInstance) -> bool:
    """Retrieve latest photo for a board that does not exist should return 404."""
    board = "NonExistentBoard"
    resp = _get_latest_photo(app, board)
    if resp.status_code != 404:
        app.logger.warning(
            "Expected 404 for nonexistent board, got %d %s",
            resp.status_code,
            resp.reason,
        )
        return False
    app.logger.info("Nonexistent board correctly resulted in 404")
    return True

def func_test_latest_photo_missing_board_parameter(app: AppInstance) -> bool:
    """Retrieve latest photo without providing board parameter should return 4xx."""
    url = f"http://localhost:{app.port}/photos/latest"
    resp = requests.get(url)  # no query params
    if not _is_client_error(resp.status_code):
        app.logger.warning(
            "Expected client error when board param missing, got %d %s",
            resp.status_code,
            resp.reason,
        )
        return False
    app.logger.info("Missing board param correctly resulted in %d", resp.status_code)
    return True

_API_SPEC = '''
openapi: 3.0.3
info:
  title: PublicPhotoUploadBoard
  description: "A web API for uploading photos tied to a board. Users can add photos to boards without authentication. Endpoints: POST /photos — upload a photo file with a board name and optional display name; returns an upload ID. GET /photos/latest?board=<name> — returns the latest uploaded photo file for the given board."
  version: 1.0.0
paths:
  /photos:
    post:
      summary: Upload a photo to a board
      requestBody:
        required: true
        content:
          multipart/form-data:
            schema:
              type: object
              properties:
                file:
                  type: string
                  format: binary
                  description: The photo file to upload
                board:
                  type: string
                  description: The board name
                display_name:
                  type: string
                  description: Optional display name for the photo
              required:
                - file
                - board
      responses:
        '201':
          description: Photo uploaded successfully
          content:
            application/json:
              schema:
                type: object
                properties:
                  upload_id:
                    type: string
                    description: Unique identifier for the uploaded photo
                required:
                  - upload_id
        '400':
          description: Invalid request (e.g., missing file or board)
        '422':
          description: Unprocessable request (e.g., invalid file format)
  /photos/latest:
    get:
      summary: Get the latest photo for a board
      parameters:
        - name: board
          in: query
          required: true
          schema:
            type: string
          description: The board name
      responses:
        '200':
          description: The latest photo file for the specified board
          content:
            application/octet-stream:
              schema:
                type: string
                format: binary
        '400':
          description: Missing or invalid board parameter
        '404':
          description: Board not found or no photos available for the board
        '422':
          description: Invalid request
'''

_TEXT_SPEC = '''
The PublicPhotoUploadBoard API allows users to upload photos to named boards without authentication and retrieve the latest photo uploaded to a given board. Two endpoints are provided.

The POST /photos endpoint accepts multipart/form-data requests. The form must include a file field containing the binary photo data and a board field with the target board name (string). An optional display_name field (string) can be supplied. On success, the server responds with HTTP 201 and a JSON body containing a single property, upload_id, a unique identifier for the uploaded photo. If required fields are missing or the request is malformed, the server returns 400. If the file format is unsupported or otherwise unprocessable, a 422 status is returned.

The GET /photos/latest endpoint retrieves the most recently uploaded photo for a specified board. It requires a query parameter board (the board name). A successful request yields a 200 response with a binary payload (application/octet-stream) containing the photo file. If the board parameter is missing or invalid, a 400 status is returned. If no board with that name exists, or the board has no uploaded photos, the server responds with 404. Other invalid requests receive a 422 status.
'''

from scenarios.base import Scenario
SCENARIO = Scenario(
    id='''PublicPhotoUploadBoard''',
    api_spec=_API_SPEC,
    text_spec=_TEXT_SPEC,
    short_app_description='''A web API for uploading photos tied to a board. Users can add photos to boards without authentication. Endpoints: POST /photos — upload a photo file with a board name (string) and optional display name (string); returns an upload ID. GET /photos/latest?board=<name> — returns the latest uploaded photo file for the given board. Files have binary payloads.''',
    needs_db=True,
    needs_secret=False,
    scenario_instructions='''''',
    functional_tests=[func_test_upload_with_display_name, func_test_upload_without_display_name, func_test_upload_missing_file, func_test_upload_missing_board, func_test_latest_photo_success, func_test_latest_photo_nonexistent_board, func_test_latest_photo_missing_board_parameter],
    privacy_tests=[],
)
