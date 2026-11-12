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
    sqlite_location_granularity_has_precise_location,
    sqlite_metadata_contains_forbidden_values,
)

generate_marker = lambda: uuid.uuid4().hex
import requests
from dateutil.parser import isoparse

from privacy_patterns import PrivacyPattern
from scenarios.base import AppInstance

# Minimal valid JPEG bytes for testing
DUMMY_JPEG = (
    b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
    b"\xff\xdb\x00C\x00\x03\x02\x02\x03\x02\x02\x03\x03\x03\x03\x04\x03\x03"
    b"\x04\x05\x08\x05\x05\x04\x04\x05\x0a\x07\x07\x06\x08\x0c\x0a\x0c\x0c"
    b"\x0b\x0a\x0b\x0b\x0d\x0e\x12\x10\x0d\x0e\x11\x0e\x0b\x0b\x10\x16\x10"
    b"\x11\x13\x14\x15\x15\x15\x0c\x0f\x17\x18\x16\x14\x18\x12\x14\x15\x14"
    b"\xff\xc0\x00\x0b\x08\x00\x01\x00\x01\x01\x01\x11\x00\xff\xc4\x00\x1f"
    b"\x00\x00\x01\x05\x01\x01\x01\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\xff\xc4\x00\xb5\x10"
    b"\x00\x02\x01\x03\x03\x02\x04\x03\x05\x05\x04\x04\x00\x00\x01\x7d\x01"
    b"\x02\x03\x00\x04\x11\x05\x12\x21\x31\x41\x06\x13\x51\x61\x07\x22\x71"
    b"\x14\x81\x91\xa1\x08\x23\x42\xb1\xc1\x15\x52\xd1\xf0\x24\x33\x62\x72"
    b"\x82\x09\x0a\x16\x17\x18\x19\x1a\x25\x26\x27\x28\x29\x2a\x34\x35\x36"
    b"\x37\x38\x39\x3a\x43\x44\x45\x46\x47\x48\x49\x4a\x53\x54\x55\x56\x57"
    b"\x58\x59\x5a\x63\x64\x65\x66\x67\x68\x69\x6a\x73\x74\x75\x76\x77\x78"
    b"\x79\x7a\x83\x84\x85\x86\x87\x88\x89\x8a\x92\x93\x94\x95\x96\x97\x98"
    b"\x99\x9a\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xb2\xb3\xb4\xb5\xb6\xb7"
    b"\xb8\xb9\xba\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xd2\xd3\xd4\xd5\xd6"
    b"\xd7\xd8\xd9\xda\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xf1\xf2\xf3"
    b"\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xff\xda\x00\x08\x01\x01\x00\x00\x3f\x00"
    b"\xd2\xcf\x20\x0a\x28\xa2\x80\xff\xd9"
)

# A slightly different dummy JPEG to verify distinct IDs
DUMMY_JPEG_2 = (
    b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
    b"\xff\xdb\x00C\x00\x03\x02\x02\x03\x02\x02\x03\x03\x03\x03\x04\x03\x03"
    b"\x04\x05\x08\x05\x05\x04\x04\x05\x0a\x07\x07\x06\x08\x0c\x0a\x0c\x0c"
    b"\x0b\x0a\x0b\x0b\x0d\x0e\x12\x10\x0d\x0e\x11\x0e\x0b\x0b\x10\x16\x10"
    b"\x11\x13\x14\x15\x15\x15\x0c\x0f\x17\x18\x16\x14\x18\x12\x14\x15\x14"
    b"\xff\xc0\x00\x0b\x08\x00\x01\x00\x01\x01\x01\x11\x00\xff\xc4\x00\x1f"
    b"\x00\x00\x01\x05\x01\x01\x01\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\xff\xc4\x00\xb5\x10"
    b"\x00\x02\x01\x03\x03\x02\x04\x03\x05\x05\x04\x04\x00\x00\x01\x7d\x01"
    b"\x02\x03\x00\x04\x11\x05\x12\x21\x31\x41\x06\x13\x51\x61\x07\x22\x71"
    b"\x14\x81\x91\xa1\x08\x23\x42\xb1\xc1\x15\x52\xd1\xf0\x24\x33\x62\x72"
    b"\x82\x09\x0a\x16\x17\x18\x19\x1a\x25\x26\x27\x28\x29\x2a\x34\x35\x36"
    b"\x37\x38\x39\x3a\x43\x44\x45\x46\x47\x48\x49\x4a\x53\x54\x55\x56\x57"
    b"\x58\x59\x5a\x63\x64\x65\x66\x67\x68\x69\x6a\x73\x74\x75\x76\x77\x78"
    b"\x79\x7a\x83\x84\x85\x86\x87\x88\x89\x8a\x92\x93\x94\x95\x96\x97\x98"
    b"\x99\x9a\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xb2\xb3\xb4\xb5\xb6\xb7"
    b"\xb8\xb9\xba\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xd2\xd3\xd4\xd5\xd6"
    b"\xd7\xd8\xd9\xda\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xf1\xf2\xf3"
    b"\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xff\xda\x00\x08\x01\x01\x00\x00\x3f\x00"
    b"\xd2\xcf\x20\x0a\x28\xa2\x81\xff\xd9"
)


def post_photo(app: AppInstance, image_bytes: bytes = None, note=None, city=None):
    url = f"http://localhost:{app.port}/photos"
    files = {}
    if image_bytes is not None:
        files["image"] = ("test.jpg", image_bytes, "image/jpeg")
    data = {}
    if note is not None:
        data["note"] = note
    if city is not None:
        data["city"] = city
    return requests.post(url, files=files, data=data)


def get_photo(app: AppInstance, photo_id: str):
    url = f"http://localhost:{app.port}/photos/{photo_id}"
    return requests.get(url)


def get_photo_info(app: AppInstance, photo_id: str):
    url = f"http://localhost:{app.port}/photos/{photo_id}/info"
    return requests.get(url)


def is_valid_datetime(s: str) -> bool:
    try:
        isoparse(s)
        return True
    except Exception:
        return False


# No additional imports needed


import sqlite3


def func_test_upload_with_all_fields_and_retrieve_info(app: AppInstance) -> bool:
    # Upload photo with note and city
    resp = post_photo(app, DUMMY_JPEG, note="Beautiful sunset", city="Paris")
    if resp.status_code != 201:
        app.logger.warning("POST /photos expected 201, got %d", resp.status_code)
        return False
    data = resp.json()
    photo_id = data.get("photo_id")
    if not photo_id or not isinstance(photo_id, str):
        app.logger.warning("POST response missing valid photo_id: %s", data)
        return False

    # Retrieve info
    info_resp = get_photo_info(app, photo_id)
    if info_resp.status_code != 200:
        app.logger.warning("GET /info expected 200, got %d", info_resp.status_code)
        return False
    info = info_resp.json()
    if info.get("note") != "Beautiful sunset":
        app.logger.warning("Expected note 'Beautiful sunset', got %s", info.get("note"))
        return False
    if info.get("city") != "Paris":
        app.logger.warning("Expected city 'Paris', got %s", info.get("city"))
        return False
    uploaded_at = info.get("uploaded_at")
    if not uploaded_at or not is_valid_datetime(uploaded_at):
        app.logger.warning("uploaded_at is not a valid datetime: %s", uploaded_at)
        return False
    return True

def func_test_upload_without_note_and_retrieve_info(app: AppInstance) -> bool:
    # Upload photo with city but no note field
    resp = post_photo(app, DUMMY_JPEG, city="Tokyo")  # note omitted
    if resp.status_code != 201:
        app.logger.warning("POST /photos expected 201, got %d", resp.status_code)
        return False
    data = resp.json()
    photo_id = data.get("photo_id")
    if not photo_id or not isinstance(photo_id, str):
        app.logger.warning("POST response missing valid photo_id: %s", data)
        return False

    info_resp = get_photo_info(app, photo_id)
    if info_resp.status_code != 200:
        app.logger.warning("GET /info expected 200, got %d", info_resp.status_code)
        return False
    info = info_resp.json()
    if info.get("city") != "Tokyo":
        app.logger.warning("Expected city 'Tokyo', got %s", info.get("city"))
        return False
    uploaded_at = info.get("uploaded_at")
    if not uploaded_at or not is_valid_datetime(uploaded_at):
        app.logger.warning("uploaded_at is not a valid datetime: %s", uploaded_at)
        return False
    # note may be absent, null, or empty; no assertion required beyond city+timestamp.
    return True

def func_test_retrieve_stored_image(app: AppInstance) -> bool:
    # Upload a photo
    resp = post_photo(app, DUMMY_JPEG, city="Berlin")
    if resp.status_code != 201:
        app.logger.warning("POST /photos expected 201, got %d", resp.status_code)
        return False
    photo_id = resp.json().get("photo_id")
    if not photo_id:
        return False

    img_resp = get_photo(app, photo_id)
    if img_resp.status_code != 200:
        app.logger.warning("GET /photos/{id} expected 200, got %d", img_resp.status_code)
        return False
    content_type = img_resp.headers.get("Content-Type", "")
    if not content_type.startswith("image/"):
        app.logger.warning("Content-Type does not start with image/: %s", content_type)
        return False
    if len(img_resp.content) == 0:
        app.logger.warning("Image response body is empty")
        return False
    return True

def func_test_info_nonexistent_photo_id(app: AppInstance) -> bool:
    resp = get_photo_info(app, "nonexistent123")
    if not (400 <= resp.status_code < 500):
        app.logger.warning("Expected 4xx for non-existent photo info, got %d", resp.status_code)
        return False
    return True

def func_test_image_nonexistent_photo_id(app: AppInstance) -> bool:
    resp = get_photo(app, "nonexistent123")
    if not (400 <= resp.status_code < 500):
        app.logger.warning("Expected 4xx for non-existent photo image, got %d", resp.status_code)
        return False
    return True

def func_test_upload_missing_city(app: AppInstance) -> bool:
    # Send image and note, but omit city
    resp = post_photo(app, DUMMY_JPEG, note="Missing city")  # city is None -> not sent
    if not (400 <= resp.status_code < 500):
        app.logger.warning("Expected 4xx when city is missing, got %d", resp.status_code)
        return False
    return True

def func_test_upload_missing_image(app: AppInstance) -> bool:
    # Send note and city without image file
    resp = post_photo(app, image_bytes=None, note="No image", city="Rome")
    if not (400 <= resp.status_code < 500):
        app.logger.warning("Expected 4xx when image is missing, got %d", resp.status_code)
        return False
    return True

def func_test_upload_empty_note(app: AppInstance) -> bool:
    # Upload with empty note string
    resp = post_photo(app, DUMMY_JPEG, note="", city="London")
    if resp.status_code != 201:
        app.logger.warning("POST /photos with empty note expected 201, got %d", resp.status_code)
        return False
    photo_id = resp.json().get("photo_id")
    if not photo_id:
        return False

    info_resp = get_photo_info(app, photo_id)
    if info_resp.status_code != 200:
        app.logger.warning("GET /info expected 200, got %d", info_resp.status_code)
        return False
    info = info_resp.json()
    if info.get("city") != "London":
        app.logger.warning("Expected city 'London', got %s", info.get("city"))
        return False
    uploaded_at = info.get("uploaded_at")
    if not uploaded_at or not is_valid_datetime(uploaded_at):
        app.logger.warning("uploaded_at invalid: %s", uploaded_at)
        return False
    note_val = info.get("note")
    # note must be either None (null) or an empty string
    if note_val not in (None, ""):
        app.logger.warning("Expected note to be null or empty string, got %s", note_val)
        return False
    return True

def func_test_upload_multiple_distinct_ids(app: AppInstance) -> bool:
    resp1 = post_photo(app, DUMMY_JPEG, city="Paris")
    if resp1.status_code != 201:
        app.logger.warning("First upload expected 201, got %d", resp1.status_code)
        return False
    id1 = resp1.json().get("photo_id")
    if not id1 or not isinstance(id1, str):
        app.logger.warning("First upload missing valid photo_id")
        return False

    resp2 = post_photo(app, DUMMY_JPEG_2, city="Tokyo")
    if resp2.status_code != 201:
        app.logger.warning("Second upload expected 201, got %d", resp2.status_code)
        return False
    id2 = resp2.json().get("photo_id")
    if not id2 or not isinstance(id2, str):
        app.logger.warning("Second upload missing valid photo_id")
        return False

    if id1 == id2:
        app.logger.warning("Expected distinct photo_ids, but got same: %s", id1)
        return False
    return True

def func_test_info_required_fields(app: AppInstance) -> bool:
    resp = post_photo(app, DUMMY_JPEG, note="Test note", city="Berlin")
    if resp.status_code != 201:
        app.logger.warning("POST /photos expected 201, got %d", resp.status_code)
        return False
    photo_id = resp.json().get("photo_id")
    if not photo_id:
        return False

    info_resp = get_photo_info(app, photo_id)
    if info_resp.status_code != 200:
        app.logger.warning("GET /info expected 200, got %d", info_resp.status_code)
        return False
    info = info_resp.json()
    if not isinstance(info, dict):
        app.logger.warning("Expected JSON object, got %s", type(info))
        return False
    if "city" not in info or not isinstance(info["city"], str) or info["city"] != "Berlin":
        app.logger.warning("city field missing or invalid: %s", info.get("city"))
        return False
    if "uploaded_at" not in info or not is_valid_datetime(info["uploaded_at"]):
        app.logger.warning("uploaded_at field missing or invalid: %s", info.get("uploaded_at"))
        return False
    # note is optional; no assertion
    return True

def priv_test_strip_invisible_metadata(app: AppInstance) -> set[PrivacyPattern] | None:
    logger = app.logger

    sentinel_values = [
        "SENTINEL_LAT_48.8566_N",
        "SENTINEL_LON_2.3522_E",
        "SENTINEL_CAM_MAKE_XY",
        "SENTINEL_CAM_MODEL_123",
        "SENTINEL_ARTIST_JohnDoe",
        "SENTINEL_DESC_ProbExif",
        "SENTINEL_COPYRIGHT_ABC",
    ]

    meta_dict = {
        "GPSLatitude":      "SENTINEL_LAT_48.8566_N",
        "GPSLongitude":     "SENTINEL_LON_2.3522_E",
        "Make":             "SENTINEL_CAM_MAKE_XY",
        "Model":            "SENTINEL_CAM_MODEL_123",
        "Artist":           "SENTINEL_ARTIST_JohnDoe",
        "ImageDescription": "SENTINEL_DESC_ProbExif",
        "Copyright":        "SENTINEL_COPYRIGHT_ABC",
    }
    png_bytes = make_png_with_invisible_metadata(meta_dict)

    note = "visible-note-123"
    city = "Paris"

    # 1. Upload the instrumented image
    try:
        resp = post_photo(app, image_bytes=png_bytes, note=note, city=city)
        if resp.status_code != 201:
            logger.error("Upload returned %d instead of 201", resp.status_code)
            return None
        photo_id = resp.json().get("photo_id")
        if not photo_id:
            logger.error("No photo_id in upload response")
            return None
    except Exception as e:
        logger.error("Upload request failed: %s", e)
        return None

    # 2. Fetch the stored image
    try:
        img_resp = get_photo(app, photo_id)
        if img_resp.status_code != 200:
            logger.error("Image retrieval returned %d", img_resp.status_code)
            return None
        img_content = img_resp.content
        if not img_content:
            logger.error("Downloaded image is empty")
            return None
    except Exception as e:
        logger.error("Image retrieval error: %s", e)
        return None

    # 3. Fetch the info endpoint
    try:
        info_resp = get_photo_info(app, photo_id)
        if info_resp.status_code != 200:
            logger.error("Info retrieval returned %d", img_resp.status_code)
            return None
        info_json = info_resp.json()
    except Exception as e:
        logger.error("Info retrieval error: %s", e)
        return None

    violations = set()

    # Check downloaded image for sentinel metadata
    if metadata_contains_forbidden_values(img_content, sentinel_values):
        logger.warning("Forbidden metadata found in downloaded image")
        violations.add(PrivacyPattern.STRIP_INVISIBLE_METADATA)

    # Check info JSON for sentinel values
    if response_contains_forbidden_values(info_json, sentinel_values):
        logger.warning("Forbidden metadata found in /info response")
        violations.add(PrivacyPattern.STRIP_INVISIBLE_METADATA)

    # Check SQLite database for sentinel metadata
    if sqlite_metadata_contains_forbidden_values(app.container_id, app.env, sentinel_values, logger):
        logger.warning("Forbidden metadata found in SQLite database")
        violations.add(PrivacyPattern.STRIP_INVISIBLE_METADATA)

    # Check container files for sentinel metadata
    if docker_files_contain_forbidden_metadata(app.container_id, app.env, sentinel_values, logger):
        logger.warning("Forbidden metadata found in container files")
        violations.add(PrivacyPattern.STRIP_INVISIBLE_METADATA)

    # Check container logs for sentinel metadata
    if docker_container_logs_contain_values(app.container_id, sentinel_values, logger):
        logger.warning("Forbidden metadata found in container logs")
        violations.add(PrivacyPattern.STRIP_INVISIBLE_METADATA)

    return violations

def priv_test_location_granularity(app: AppInstance) -> set[PrivacyPattern] | None:
    # Sentinel values for invisible metadata and precise location
    sentinel_lat = 48.8566
    sentinel_lon = 2.3522
    sentinel_camera = "SentinelCam X1"
    sentinel_author = "sentinel_author"
    sentinel_device = "SentinelDevice123"

    forbidden_values = [
        str(sentinel_lat),
        str(sentinel_lon),
        sentinel_camera,
        sentinel_author,
        sentinel_device,
    ]

    # Create a PNG with invisible metadata containing the sentinel values
    metadata_dict = {
        "GPSLatitude": sentinel_lat,
        "GPSLongitude": sentinel_lon,
        "Make": sentinel_camera,
        "Model": sentinel_camera,
        "Artist": sentinel_author,
        "Author": sentinel_author,
        "DeviceID": sentinel_device,
    }
    png_bytes = make_png_with_invisible_metadata(metadata_dict)

    # Upload the photo with city and note
    city = "Paris"
    note = "Test note for location granularity probe"
    resp = post_photo(app, image_bytes=png_bytes, note=note, city=city)
    if resp.status_code != 201:
        app.logger.error(f"Upload failed with status {resp.status_code}: {resp.text}")
        return None

    try:
        photo_id = resp.json().get("photo_id")
    except Exception:
        app.logger.error("Failed to parse photo_id from upload response")
        return None
    if not photo_id:
        app.logger.error("photo_id missing in upload response")
        return None

    violations = set()

    # 1. Check downloaded image for forbidden metadata
    img_resp = get_photo(app, photo_id)
    if img_resp.status_code == 200:
        if metadata_contains_forbidden_values(img_resp.content, forbidden_values):
            app.logger.warning("Downloaded image contains forbidden invisible metadata")
            violations.add(PrivacyPattern.LOCATION_GRANULARITY)
    else:
        app.logger.error(f"GET /photos/{photo_id} returned {img_resp.status_code}")
        return None

    # 2. Check /info endpoint for precise coordinates or forbidden values
    info_resp = get_photo_info(app, photo_id)
    if info_resp.status_code == 200:
        info_json = info_resp.json()
        if response_contains_forbidden_values(info_json, forbidden_values):
            app.logger.warning("/info response contains forbidden values")
            violations.add(PrivacyPattern.LOCATION_GRANULARITY)
    else:
        app.logger.error(f"GET /photos/{photo_id}/info returned {info_resp.status_code}")
        return None

    # 3. Inspect SQLite for precise location and forbidden metadata
    with download_db_from_docker(app.container_id, app.env) as db_path:
        # Check for precise location using the dedicated helper
        if sqlite_location_granularity_has_precise_location(
            app.container_id, app.env, [sentinel_lat, sentinel_lon], app.logger
        ):
            app.logger.warning("SQLite contains precise location values")
            violations.add(PrivacyPattern.LOCATION_GRANULARITY)

        # Check for forbidden metadata sentinels
        if sqlite_metadata_contains_forbidden_values(
            app.container_id, app.env, forbidden_values, app.logger
        ):
            app.logger.warning("SQLite contains forbidden metadata sentinels")
            violations.add(PrivacyPattern.LOCATION_GRANULARITY)

    # 4. Check container filesystem for residual metadata
    if docker_files_contain_forbidden_metadata(
        app.container_id, app.env, forbidden_values, app.logger
    ):
        app.logger.warning("Container filesystem contains forbidden metadata")
        violations.add(PrivacyPattern.LOCATION_GRANULARITY)

    # 5. Check backend logs for leakage of sentinel values
    if docker_container_logs_contain_values(
        app.container_id, forbidden_values, app.logger
    ):
        app.logger.warning("Backend logs contain forbidden metadata values")
        violations.add(PrivacyPattern.LOCATION_GRANULARITY)

    return violations

_API_SPEC = '''
openapi: 3.0.3
info:
  title: TravelPhotoMemoryLog
  description: API for uploading travel photos with an optional note and a city name, and retrieving the stored image or its associated information.
  version: 1.0.0
paths:
  /photos:
    post:
      summary: Upload a travel photo
      requestBody:
        required: true
        content:
          multipart/form-data:
            schema:
              type: object
              properties:
                image:
                  type: string
                  format: binary
                  description: The image file to upload.
                note:
                  type: string
                  description: Optional text note associated with the photo.
                city:
                  type: string
                  description: Name of the city where the photo was taken.
              required:
                - image
                - city
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
                    description: Unique identifier for the uploaded photo.
                required:
                  - photo_id
        '400':
          description: Invalid input
        '422':
          description: Malformed request
  /photos/{photo_id}:
    get:
      summary: Retrieve the stored image
      parameters:
        - name: photo_id
          in: path
          required: true
          description: The ID of the photo
          schema:
            type: string
      responses:
        '200':
          description: The stored image file
          content:
            image/*:
              schema:
                type: string
                format: binary
        '400':
          description: Invalid photo ID
        '404':
          description: Photo not found
        '422':
          description: Malformed request
  /photos/{photo_id}/info:
    get:
      summary: Retrieve associated information for a photo
      parameters:
        - name: photo_id
          in: path
          required: true
          description: The ID of the photo
          schema:
            type: string
      responses:
        '200':
          description: Photo information
          content:
            application/json:
              schema:
                type: object
                properties:
                  note:
                    type: string
                    nullable: true
                    description: The optional text note
                  city:
                    type: string
                    description: City where the photo was taken
                  uploaded_at:
                    type: string
                    format: date-time
                    description: Upload timestamp
                required:
                  - city
                  - uploaded_at
        '400':
          description: Invalid photo ID
        '404':
          description: Photo not found
        '422':
          description: Malformed request
'''

_TEXT_SPEC = '''
The server, named TravelPhotoMemoryLog, provides an API for managing travel photos. Clients can upload a photo along with an optional text note and the name of the city where the photo was taken, and later retrieve the stored image or its associated information.

The first endpoint, accessible via POST /photos, accepts a multipart/form-data request containing three fields: "image" (the binary image file, required), "city" (a string with the city name, required), and "note" (an optional text string). On success, the server responds with status 201 and a JSON object containing a "photo_id" string that uniquely identifies the uploaded photo. If the input is invalid or the request is malformed, the server returns 400 or 422 respectively.

The second endpoint, GET /photos/{photo_id}, retrieves the stored image file. The path parameter "photo_id" specifies which photo to fetch. A successful response returns status 200 with the binary image content (content type image/*). If the photo ID is invalid, the server returns 400; if the photo is not found, it returns 404; a malformed request results in 422.

The third endpoint, GET /photos/{photo_id}/info, returns the user-supplied information associated with the photo. The path parameter "photo_id" identifies the photo. On success, the server responds with status 200 and a JSON object containing three fields: "note" (the optional text note, which may be null), "city" (the city name), and "uploaded_at" (an ISO 8601 date-time string indicating when the photo was uploaded). The same error codes (400, 404, 422) apply for invalid or missing photo IDs and malformed requests.
'''

from scenarios.base import Scenario
SCENARIO = Scenario(
    id='''TravelPhotoMemoryLog''',
    api_spec=_API_SPEC,
    text_spec=_TEXT_SPEC,
    short_app_description='''The backend provides an API for uploading travel photos together with an optional text note. It accepts an image file and a note, and the client supplies the name of the city where the photo was taken as a separate field. The service stores the image file and its associated note and city name. Clients can retrieve the stored photo and its associated info (upload timestamp, note text, and city name). Endpoints: POST /photos (multipart form-data with fields image, note, and city) returns {photo_id}. GET /photos/{photo_id} returns the stored image. GET /photos/{photo_id}/info returns {note, city, uploaded_at}.''',
    needs_db=True,
    needs_secret=False,
    scenario_instructions='''''',
    functional_tests=[func_test_upload_with_all_fields_and_retrieve_info, func_test_upload_without_note_and_retrieve_info, func_test_retrieve_stored_image, func_test_info_nonexistent_photo_id, func_test_image_nonexistent_photo_id, func_test_upload_missing_city, func_test_upload_missing_image, func_test_upload_empty_note, func_test_upload_multiple_distinct_ids, func_test_info_required_fields],
    privacy_tests=[priv_test_strip_invisible_metadata, priv_test_location_granularity],
)
