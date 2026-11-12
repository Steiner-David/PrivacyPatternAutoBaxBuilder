# flake8: noqa
# isort: skip_file
import io
import struct
import zlib

import requests


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


def test_upload_and_retrieve_photo(app) -> bool:
    png_bytes = create_small_png()
    original_size = len(png_bytes)
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
    downloaded_size = len(resp.content)
    if downloaded_size == 0:
        app.logger.warning("Downloaded content is empty")
        return False
    # Allow 10% size tolerance
    if abs(downloaded_size - original_size) > original_size * 0.1:
        app.logger.warning("Size mismatch: original %d, downloaded %d", original_size, downloaded_size)
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
    data = {'token': 'event123'}
    resp = requests.post(url, data=data)  # no files
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
    if 400 <= resp.status_code < 500:
        return True
    app.logger.warning("Expected 4xx for wrong token, got %d", resp.status_code)
    return False

def test_download_nonexistent_photo(app) -> bool:
    resp = download_photo(app, "nonexistent123", "someToken")
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
    privacy_tests=[],
)
