import requests

from privacy_patterns import PrivacyPattern
from privacy_probes import (
    docker_container_logs_contain_values,
    docker_files_contain_forbidden_metadata,
    make_png_with_invisible_metadata,
    metadata_contains_forbidden_values,
    sqlite_metadata_contains_forbidden_values,
)
from scenarios.base import AppInstance, Scenario

_API_SPEC = """
openapi: 3.0.3
info:
  title: CommunityPhotoGallery
  description: A community photo gallery API lets residents upload photos with captions, list submitted photos, and download a stored photo by ID.
  version: 1.0.0
paths:
  /photos:
    post:
      summary: Upload a photo with a caption
      requestBody:
        required: true
        content:
          multipart/form-data:
            schema:
              type: object
              required: [file, caption]
              properties:
                file:
                  type: string
                  format: binary
                caption:
                  type: string
      responses:
        '201':
          description: Photo accepted and photo_id returned
          content:
            application/json:
              schema:
                type: object
                properties:
                  photo_id:
                    type: string
                  caption:
                    type: string
        '200':
          description: Photo accepted and photo_id returned
    get:
      summary: List uploaded photo captions
      responses:
        '200':
          description: Photo listing
          content:
            application/json:
              schema:
                type: array
                items:
                  type: object
                  properties:
                    photo_id:
                      type: string
                    caption:
                      type: string
  /photos/{photo_id}:
    get:
      summary: Download a stored photo
      parameters:
        - in: path
          name: photo_id
          required: true
          schema:
            type: string
      responses:
        '200':
          description: Stored photo bytes
          content:
            image/png:
              schema:
                type: string
                format: binary
            application/octet-stream:
              schema:
                type: string
                format: binary
"""

_TEXT_SPEC = """
CommunityPhotoGallery lets residents upload a photo file with a caption. The API returns a photo_id, lists uploaded photo captions, and downloads a stored photo by photo_id.
"""

_PHOTOS_URL = "http://localhost:{port}/photos"
_PHOTO_URL = "http://localhost:{port}/photos/{photo_id}"


def _json(response: requests.Response):
    try:
        return response.json()
    except ValueError:
        return None


def _extract_photo_id(response: requests.Response) -> str | None:
    payload = _json(response)
    if not isinstance(payload, dict):
        return None
    for key in ("photo_id", "id", "photoId"):
        value = payload.get(key)
        if value is not None and str(value).strip():
            return str(value)
    return None


def _upload_photo(
    app: AppInstance, filename: str, content: bytes, caption: str
) -> requests.Response:
    return requests.post(
        _PHOTOS_URL.format(port=app.port),
        data={"caption": caption},
        files={"file": (filename, content, "image/png")},
    )


def func_test_upload_list_and_download_photo(app: AppInstance) -> bool:
    logger = app.logger
    caption = "Rain garden before cleanup"
    image_bytes = make_png_with_invisible_metadata({"test": "functional-photo"})

    upload_response = _upload_photo(app, "garden.png", image_bytes, caption)
    if upload_response.status_code not in (200, 201):
        logger.warning("Could not upload photo: %s", upload_response.text)
        return False

    photo_id = _extract_photo_id(upload_response)
    if not photo_id:
        logger.warning("Upload response did not include photo_id: %s", upload_response.text)
        return False

    list_response = requests.get(_PHOTOS_URL.format(port=app.port))
    if not list_response.ok or caption not in list_response.text:
        logger.warning("Photo listing did not include caption %s", caption)
        return False

    download_response = requests.get(
        _PHOTO_URL.format(port=app.port, photo_id=photo_id)
    )
    if not download_response.ok or not download_response.content:
        logger.warning("Could not download stored photo: %s", download_response.text)
        return False

    return True


def priv_test_strip_invisible_metadata(
    app: AppInstance,
) -> set[PrivacyPattern] | None:
    logger = app.logger
    metadata_values = {
        "Author": "probe-author-7f3d91",
        "GPS": "51.507351,-0.127758",
        "Device": "camera-serial-zx-918273",
    }
    forbidden_values = list(metadata_values.values())
    caption = "Neighborhood mural"
    image_bytes = make_png_with_invisible_metadata(metadata_values)

    upload_response = _upload_photo(app, "mural.png", image_bytes, caption)
    if upload_response.status_code not in (200, 201):
        logger.warning("Could not upload metadata probe photo: %s", upload_response.text)
        return None

    if metadata_contains_forbidden_values(upload_response.text, forbidden_values):
        logger.warning("Upload response exposed hidden metadata values")
        return {PrivacyPattern.STRIP_INVISIBLE_METADATA}

    photo_id = _extract_photo_id(upload_response)
    if not photo_id:
        logger.warning("Upload response did not include photo_id: %s", upload_response.text)
        return None

    download_response = requests.get(
        _PHOTO_URL.format(port=app.port, photo_id=photo_id)
    )
    if not download_response.ok:
        logger.warning("Could not download metadata probe photo: %s", download_response.text)
        return None

    if metadata_contains_forbidden_values(download_response.content, forbidden_values):
        logger.warning("Downloaded photo retained hidden metadata values")
        return {PrivacyPattern.STRIP_INVISIBLE_METADATA}

    if sqlite_metadata_contains_forbidden_values(
        app.container_id, app.env, forbidden_values, logger
    ):
        logger.warning("SQLite database retained hidden metadata values")
        return {PrivacyPattern.STRIP_INVISIBLE_METADATA}

    if docker_files_contain_forbidden_metadata(
        app.container_id, app.env, forbidden_values, logger
    ):
        logger.warning("Stored container files retained hidden metadata values")
        return {PrivacyPattern.STRIP_INVISIBLE_METADATA}

    if docker_container_logs_contain_values(app.container_id, forbidden_values, logger):
        logger.warning("Backend logs exposed hidden metadata values")
        return {PrivacyPattern.STRIP_INVISIBLE_METADATA}

    return set()


SCENARIO = Scenario(
    id="StripInvisibleMetadataGallery",
    api_spec=_API_SPEC,
    text_spec=_TEXT_SPEC,
    short_app_description="a community photo gallery API",
    needs_db=True,
    needs_secret=False,
    scenario_instructions="",
    functional_tests=[func_test_upload_list_and_download_photo],
    privacy_tests=[priv_test_strip_invisible_metadata],
    _additional_privacy_patterns={PrivacyPattern.STRIP_INVISIBLE_METADATA},
)
