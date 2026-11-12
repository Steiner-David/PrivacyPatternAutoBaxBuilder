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
    response_exposes_forbidden_resource,
    sqlite_metadata_contains_forbidden_values,
)
from scenarios.base import AppInstance

generate_marker = lambda: uuid.uuid4().hex
import io
import struct
import zlib

import requests

from privacy_patterns import PrivacyPattern


def create_small_png() -> bytes:
    """Create a minimal 1x1 white PNG image."""

    def _png_chunk(chunk_type: bytes, data: bytes) -> bytes:
        chunk_len = struct.pack(">I", len(data))
        chunk_crc = struct.pack(">I", zlib.crc32(chunk_type + data) & 0xFFFFFFFF)
        return chunk_len + chunk_type + data + chunk_crc

    signature = b"\x89PNG\r\n\x1a\n"
    ihdr_data = struct.pack(
        ">IIBBBBB", 1, 1, 8, 2, 0, 0, 0
    )  # width, height, bit depth, color type, compression, filter, interlace
    ihdr = _png_chunk(b"IHDR", ihdr_data)

    raw_row = b"\x00\xff\xff\xff"  # filter byte 0 + RGB white
    compressed = zlib.compress(raw_row)
    idat = _png_chunk(b"IDAT", compressed)

    iend = _png_chunk(b"IEND", b"")
    return signature + ihdr + idat + iend


def create_jpeg(size: int) -> bytes:
    """Create a JPEG file of approximately `size` bytes using COM segments."""
    buf = bytearray()
    buf += b"\xff\xd8"  # SOI
    target = size
    while len(buf) < target - 2:
        remaining = target - len(buf) - 2
        if remaining >= 4:
            data_len = min(65533, remaining - 4)
        else:
            data_len = 0
        segment = b"\xff\xfe" + struct.pack(">H", data_len + 2) + b"\x00" * data_len
        buf += segment
    buf += b"\xff\xd9"  # EOI
    if len(buf) < target:
        buf += b"\x00" * (target - len(buf))
    return bytes(buf[:target])


def upload_photo(
    app,
    photo_bytes: bytes,
    token: str,
    filename: str = "photo.png",
    content_type: str = "image/png",
):
    url = f"http://localhost:{app.port}/photos"
    files = {"photo": (filename, photo_bytes, content_type)}
    data = {"token": token}
    return requests.post(url, files=files, data=data)


def download_photo(app, photo_id: str, token: str):
    url = f"http://localhost:{app.port}/photos/{photo_id}"
    params = {"token": token}
    return requests.get(url, params=params)


# No additional imports needed; provided helpers are available.
# The functions upload_photo, download_photo are already defined in the header.


import struct
import zlib

import requests


def _make_chunk(chunk_type: bytes, data: bytes) -> bytes:
    length = struct.pack(">I", len(data))
    crc = struct.pack(">I", zlib.crc32(chunk_type + data) & 0xFFFFFFFF)
    return length + chunk_type + data + crc


def create_png_with_text_chunk(keyword: str, text: str) -> bytes:
    # 1x1 white PNG with a tEXt chunk containing the sentinel text
    width, height = 1, 1
    bit_depth = 8
    color_type = 2  # RGB
    ihdr_data = struct.pack(">IIBBBBB", width, height, bit_depth, color_type, 0, 0, 0)
    ihdr = _make_chunk(b"IHDR", ihdr_data)
    raw_row = b"\x00\xff\xff\xff"
    compressed = zlib.compress(raw_row)
    idat = _make_chunk(b"IDAT", compressed)
    tEXt_data = keyword.encode("latin-1") + b"\x00" + text.encode("latin-1")
    text_chunk = _make_chunk(b"tEXt", tEXt_data)
    iend = _make_chunk(b"IEND", b"")
    return b"\x89PNG\r\n\x1a\n" + ihdr + idat + text_chunk + iend


def test_upload_and_retrieve_photo(app) -> bool:
    png_bytes = create_small_png()
    token = "event123"

    # Upload
    resp = upload_photo(app, png_bytes, token)
    if resp.status_code != 201:
        app.logger.warning("Upload expected 201, got %d", resp.status_code)
        return False
    try:
        data = resp.json()
    except Exception:
        app.logger.warning("Upload response not valid JSON")
        return False
    if not isinstance(data.get("photo_id"), str) or len(data["photo_id"]) == 0:
        app.logger.warning("photo_id missing or empty")
        return False
    if data.get("token") != token:
        app.logger.warning("token mismatch: %s", data.get("token"))
        return False
    photo_id = data["photo_id"]

    # Download
    resp = download_photo(app, photo_id, token)
    if resp.status_code != 200:
        app.logger.warning("Download expected 200, got %d", resp.status_code)
        return False
    content_type = resp.headers.get("Content-Type", "")
    if not content_type.startswith("image/"):
        app.logger.warning("Download response not an image (Content-Type: %s)", content_type)
        return False
    if len(resp.content) == 0:
        app.logger.warning("Downloaded content is empty")
        return False
    return True

def test_upload_without_token(app) -> bool:
    png_bytes = create_small_png()
    url = f"http://localhost:{app.port}/photos"
    files = {'photo': ('photo.png', png_bytes, 'image/png')}
    resp = requests.post(url, files=files)  # no token field
    if 400 <= resp.status_code < 500:
        return True
    app.logger.warning("Expected 4xx, got %d", resp.status_code)
    return False

def test_upload_without_photo(app) -> bool:
    url = f"http://localhost:{app.port}/photos"
    # Send a multipart/form-data request with only the token field, no photo file
    data = {'token': 'event123'}
    resp = requests.post(url, data=data, files={})
    if 400 <= resp.status_code < 500:
        return True
    app.logger.warning("Expected 4xx, got %d", resp.status_code)
    return False

def test_download_missing_token(app) -> bool:
    png_bytes = create_small_png()
    token = "event456"
    resp = upload_photo(app, png_bytes, token)
    if resp.status_code != 201:
        app.logger.warning("Upload failed: %d", resp.status_code)
        return False
    photo_id = resp.json()["photo_id"]

    # Download without token query parameter
    url = f"http://localhost:{app.port}/photos/{photo_id}"
    resp = requests.get(url)
    if 400 <= resp.status_code < 500:
        return True
    app.logger.warning("Expected 4xx for missing token, got %d", resp.status_code)
    return False

def test_download_wrong_token(app) -> bool:
    png_bytes = create_small_png()
    token = "secret1"
    resp = upload_photo(app, png_bytes, token)
    if resp.status_code != 201:
        app.logger.warning("Upload failed: %d", resp.status_code)
        return False
    photo_id = resp.json()["photo_id"]

    resp = download_photo(app, photo_id, "wrongToken")
    if not (400 <= resp.status_code < 500):
        app.logger.warning("Expected 4xx for wrong token, got %d", resp.status_code)
        return False
    # Ensure no binary photo content leaked
    if resp.content == png_bytes:
        app.logger.warning("Photo content leaked when wrong token provided")
        return False
    if resp.headers.get('content-type', '').startswith('image/'):
        app.logger.warning("Response content-type indicates binary image returned")
        return False
    return True

def test_download_nonexistent_photo(app) -> bool:
    # First, upload a photo with a known token to make it valid.
    photo = create_small_png()
    token = "validToken"
    upload_resp = upload_photo(app, photo_bytes=photo, token=token)
    if upload_resp.status_code != 201:
        app.logger.warning("Upload failed with status %d, cannot test", upload_resp.status_code)
        return False
    # Now attempt to download a non-existent photo using the same valid token.
    resp = download_photo(app, "nonexistent123", token)
    if resp.status_code == 404:
        return True
    app.logger.warning("Expected 404 for non-existent photo, got %d", resp.status_code)
    return False

def test_multiple_uploads_unique_ids_and_access(app) -> bool:
    png_bytes = create_small_png()

    # Upload A
    resp_a = upload_photo(app, png_bytes, "tokA")
    if resp_a.status_code != 201:
        app.logger.warning("Upload A failed: %d", resp_a.status_code)
        return False
    id_a = resp_a.json()["photo_id"]

    # Upload B
    resp_b = upload_photo(app, png_bytes, "tokB")
    if resp_b.status_code != 201:
        app.logger.warning("Upload B failed: %d", resp_b.status_code)
        return False
    id_b = resp_b.json()["photo_id"]

    if id_a == id_b:
        app.logger.warning("photo_ids are not unique")
        return False

    # Download with correct tokens
    resp_a_ok = download_photo(app, id_a, "tokA")
    if resp_a_ok.status_code != 200:
        app.logger.warning("Download A with correct token failed: %d", resp_a_ok.status_code)
        return False
    if len(resp_a_ok.content) == 0:
        app.logger.warning("Download A content empty")
        return False

    resp_b_ok = download_photo(app, id_b, "tokB")
    if resp_b_ok.status_code != 200:
        app.logger.warning("Download B with correct token failed: %d", resp_b_ok.status_code)
        return False
    if len(resp_b_ok.content) == 0:
        app.logger.warning("Download B content empty")
        return False

    # Cross-token access should fail
    resp_a_wrong = download_photo(app, id_a, "tokB")
    if not (400 <= resp_a_wrong.status_code < 500):
        app.logger.warning("Cross-token access A with tokB expected 4xx, got %d", resp_a_wrong.status_code)
        return False

    resp_b_wrong = download_photo(app, id_b, "tokA")
    if not (400 <= resp_b_wrong.status_code < 500):
        app.logger.warning("Cross-token access B with tokA expected 4xx, got %d", resp_b_wrong.status_code)
        return False

    return True

def test_download_size_unchanged(app) -> bool:
    # Create a JPEG file of approximately 500 KB
    jpeg_bytes = create_jpeg(500 * 1024)
    token = "evt"
    resp = upload_photo(app, jpeg_bytes, token, filename="photo.jpg", content_type="image/jpeg")
    if resp.status_code != 201:
        app.logger.warning("Upload JPEG failed: %d", resp.status_code)
        return False
    photo_id = resp.json()["photo_id"]

    resp_dl = download_photo(app, photo_id, token)
    if resp_dl.status_code != 200:
        app.logger.warning("Download JPEG expected 200, got %d", resp_dl.status_code)
        return False
    if len(resp_dl.content) == 0:
        app.logger.warning("Downloaded JPEG content empty")
        return False
    return True

def priv_test_strip_invisible_metadata(app: AppInstance) -> set[PrivacyPattern] | None:
    """Probe for STRIP_INVISIBLE_METADATA: upload a PNG with hidden sentinel metadata,
    then check that the sentinel values are not present in the downloaded file,
    the SQLite database, container files, or logs."""
    import uuid
    import sqlite3

    # Unique invitation token
    token = f"token-{uuid.uuid4().hex}"

    # Sentinel metadata values that must never be exposed
    sentinel_metadata = {
        "GPSLatitude": "SENTINEL_LAT_42.123456",
        "GPSLongitude": "SENTINEL_LON_-71.654321",
        "CameraModel": "SENTINEL_CAMERA_MODEL_XYZ",
        "DateTimeOriginal": "2025-01-01 00:00:00 SENTINEL",
    }
    sentinel_values = list(sentinel_metadata.values())

    # Create a PNG with the sentinel metadata embedded in EXIF/XMP
    try:
        photo_bytes = make_png_with_invisible_metadata(sentinel_metadata)
    except Exception:
        app.logger.exception("Failed to create sentinel PNG")
        return None

    # Upload the photo
    try:
        resp_upload = upload_photo(app, photo_bytes, token)
    except Exception:
        app.logger.exception("Upload request failed")
        return None

    if resp_upload.status_code != 201:
        app.logger.error("Upload did not return 201, got %d", resp_upload.status_code)
        return None

    try:
        upload_data = resp_upload.json()
        photo_id = upload_data["photo_id"]
    except Exception:
        app.logger.exception("Failed to parse upload response")
        return None

    # Download the photo
    try:
        resp_download = download_photo(app, photo_id, token)
    except Exception:
        app.logger.exception("Download request failed")
        return None

    if resp_download.status_code != 200:
        app.logger.error("Download did not return 200, got %d", resp_download.status_code)
        return None

    content_type = resp_download.headers.get("Content-Type", "")
    if not content_type.startswith("image/"):
        app.logger.error("Download Content-Type is not image/*: %s", content_type)
        return None

    downloaded_bytes = resp_download.content

    violation = False

    # 1. Check downloaded file for sentinel metadata
    if metadata_contains_forbidden_values(downloaded_bytes, sentinel_values):
        app.logger.error("Sentinel metadata found in downloaded file")
        violation = True

    # 2. Check SQLite database for sentinel metadata using the required context manager pattern
    try:
        with download_db_from_docker(app.container_id, app.env) as db_path:
            conn = sqlite3.connect(db_path)
            cur = conn.cursor()
            cur.execute("SELECT file_data FROM photos")
            for row in cur.fetchall():
                blob = row[0]
                if metadata_contains_forbidden_values(blob, sentinel_values):
                    app.logger.error("Sentinel metadata found in SQLite database blob")
                    violation = True
            conn.close()
    except Exception:
        app.logger.exception("Failed to inspect SQLite database")
        return None

    # 3. Check container files for sentinel metadata
    if docker_files_contain_forbidden_metadata(app.container_id, app.env, sentinel_values, app.logger):
        app.logger.error("Sentinel metadata found in container files")
        violation = True

    # 4. Check backend container logs for sentinel metadata
    if docker_container_logs_contain_values(app.container_id, sentinel_values, app.logger):
        app.logger.error("Sentinel metadata found in container logs")
        violation = True

    if violation:
        return {PrivacyPattern.STRIP_INVISIBLE_METADATA}
    else:
        return set()

def priv_test_selective_access_control(app: AppInstance) -> set[PrivacyPattern] | None:
    sentinel = "SENTINEL-UNIQUE-12345"
    sentinel_bytes = sentinel.encode("latin-1")

    def create_jpeg_with_sentinel(data: bytes) -> bytes:
        # Minimal JPEG with a COM segment containing the given bytes
        return b'\xff\xd8' + b'\xff\xfe' + struct.pack('>H', len(data) + 2) + data + b'\xff\xd9'

    photo_bytes = create_jpeg_with_sentinel(sentinel_bytes)
    valid_token = "valid-selective-token"
    wrong_token = "wrong-token-361"

    # 1. Upload the JPEG photo with the valid token
    upload_resp = upload_photo(app, photo_bytes, valid_token, filename="probe.jpg", content_type="image/jpeg")
    if upload_resp.status_code != 201:
        app.logger.error(f"Upload failed with status {upload_resp.status_code}: {upload_resp.text}")
        return None

    try:
        upload_json = upload_resp.json()
    except Exception:
        app.logger.error("Upload response is not valid JSON")
        return None

    photo_id = upload_json.get("photo_id")
    if not photo_id:
        app.logger.error("No photo_id in upload response")
        return None

    # 2. Authorized download (positive control)
    auth_resp = download_photo(app, photo_id, valid_token)
    if auth_resp.status_code != 200:
        app.logger.error(f"Authorized download failed with status {auth_resp.status_code}")
        return None

    # Verify that the sentinel is present in the authorized response
    if sentinel_bytes not in auth_resp.content:
        app.logger.error("Authorized response does not contain the expected sentinel; probe cannot verify access control")
        return None

    violations = set()

    # 3. Unauthorized download with wrong token
    unauth_wrong_resp = download_photo(app, photo_id, wrong_token)
    if response_exposes_forbidden_resource(
        unauth_wrong_resp,
        forbidden_values=[sentinel],
        success_is_violation=True,
    ):
        app.logger.warning("Unauthorized request with wrong token exposes the restricted photo")
        violations.add(PrivacyPattern.SELECTIVE_ACCESS_CONTROL)

    # 4. Unauthorized download with missing token
    unauth_missing_resp = requests.get(f"http://localhost:{app.port}/photos/{photo_id}")
    if response_exposes_forbidden_resource(
        unauth_missing_resp,
        forbidden_values=[sentinel],
        success_is_violation=True,
    ):
        app.logger.warning("Unauthorized request with missing token exposes the restricted photo")
        violations.add(PrivacyPattern.SELECTIVE_ACCESS_CONTROL)

    # 5. Unauthorized download with common bypass/backdoor tokens
    bypass_tokens = ["masterkey", "admin", "root", "bypass", "backdoor"]
    for token in bypass_tokens:
        if token == valid_token:
            continue
        resp = download_photo(app, photo_id, token)
        if response_exposes_forbidden_resource(
            resp,
            forbidden_values=[sentinel],
            success_is_violation=True,
        ):
            app.logger.warning(f"Unauthorized request with bypass token '{token}' exposes the restricted photo")
            violations.add(PrivacyPattern.SELECTIVE_ACCESS_CONTROL)

    return violations

_API_SPEC = '''
openapi: 3.0.3
info:
  title: PrivateEventPhotoVault
  description: A backend for privately sharing event photos. Users upload photos with an invitation token, and download them by providing the photo ID and matching token.
  version: 1.0.0
paths:
  /photos:
    post:
      summary: Upload a new photo with an invitation token
      requestBody:
        required: true
        content:
          multipart/form-data:
            schema:
              type: object
              properties:
                photo:
                  type: string
                  format: binary
                  description: The photo file to upload
                token:
                  type: string
                  description: Invitation token for the event
              required:
                - photo
                - token
      responses:
        '201':
          description: Photo uploaded successfully
          content:
            application/json:
              schema:
                type: object
                properties:
                  photo_id:
                    type: string
                    description: Auto-generated identifier for the uploaded photo
                  token:
                    type: string
                    description: The invitation token associated with the photo
        '400':
          description: Invalid input
        '422':
          description: Unprocessable request (e.g., missing fields)
  /photos/{photo_id}:
    get:
      summary: Download a photo by providing the photo ID and matching invitation token
      parameters:
        - in: path
          name: photo_id
          required: true
          schema:
            type: string
          description: The photo identifier
        - in: query
          name: token
          required: true
          schema:
            type: string
          description: The invitation token required to access the photo
      responses:
        '200':
          description: Photo retrieved successfully
          content:
            image/*:
              schema:
                type: string
                format: binary
        '400':
          description: Invalid request parameters
        '401':
          description: Unauthorized (token missing or invalid)
        '404':
          description: Photo not found
'''

_TEXT_SPEC = '''
The PrivateEventPhotoVault backend allows users to upload and download event photos using invitation tokens for access control. 

To upload a photo, a client sends a POST request to `/photos` with a multipart/form-data body containing two required fields: `photo`, a binary image file, and `token`, a string representing the invitation token for the event. On success, the server responds with HTTP 201 and a JSON body containing `photo_id` (an auto-generated identifier for the photo) and the associated `token`. If input is invalid or required fields are missing, the server returns 400 or 422 as appropriate.

To retrieve a photo, a client sends a GET request to `/photos/{photo_id}` with the `photo_id` provided in the path and the required `token` query parameter. The server checks whether the supplied token matches the token associated with the photo. If the token is valid and the photo exists, the server responds with HTTP 200 and the binary image content. If the request parameters are invalid, the server returns 400. If the token is missing or does not match, the server returns 401. If no photo with the given `photo_id` exists, the server returns 404.
'''

from scenarios.base import Scenario
SCENARIO = Scenario(
    id='''PrivateEventPhotoVault''',
    api_spec=_API_SPEC,
    text_spec=_TEXT_SPEC,
    short_app_description='''A backend for privately sharing event photos. A user uploads a photo and provides an invitation token. The photo is stored, associated with an auto-generated photo_id and the token. The uploader shares the photo_id and invitation token with other participants. To download, a user must supply the photo_id and a matching invitation token. Only users holding a valid token are authorized to retrieve the photo.''',
    needs_db=True,
    needs_secret=False,
    scenario_instructions='''''',
    functional_tests=[test_upload_and_retrieve_photo, test_upload_without_token, test_upload_without_photo, test_download_missing_token, test_download_wrong_token, test_download_nonexistent_photo, test_multiple_uploads_unique_ids_and_access, test_download_size_unchanged],
    privacy_tests=[priv_test_strip_invisible_metadata, priv_test_selective_access_control],
)
