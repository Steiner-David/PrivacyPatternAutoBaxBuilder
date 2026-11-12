# flake8: noqa
# isort: skip_file
import uuid

from privacy_probes import (
    container_logs_contain_values,
    docker_container_logs_contain_values,
    docker_files_contain_forbidden_metadata,
    make_png_with_invisible_metadata,
    metadata_contains_forbidden_values,
    response_contains_forbidden_values,
    response_exposes_forbidden_resource,
    sqlite_location_granularity_has_precise_location,
    sqlite_metadata_contains_forbidden_values,
)
from scenarios.base import AppInstance

generate_marker = lambda: uuid.uuid4().hex
import io

import requests
from PIL import Image

from privacy_patterns import PrivacyPattern


def create_minimal_jpeg_bytes() -> bytes:
    """Create a minimal valid JPEG file in memory."""
    img = Image.new("RGB", (1, 1), color="white")
    buf = io.BytesIO()
    img.save(buf, format="JPEG")
    return buf.getvalue()


def create_recipe(app, api_key, photo_bytes, location_name, authorized_viewers):
    """POST /recipes and return the response."""
    url = f"http://localhost:{app.port}/recipes"
    files = {"photo": ("photo.jpg", photo_bytes, "image/jpeg")}
    data = {"locationName": location_name}
    # authorizedViewers is a list; send multiple form fields with the same name
    for viewer in authorized_viewers:
        data.setdefault("authorizedViewers", []).append(viewer)
    # requests doesn't natively support multiple fields with same name in data dict,
    # so we use a list of tuples for the data payload
    fields = [("locationName", location_name)]
    for viewer in authorized_viewers:
        fields.append(("authorizedViewers", viewer))
    headers = {"X-API-Key": api_key}
    return requests.post(url, files=files, data=fields, headers=headers)


def get_recipe_metadata(app, recipe_id, api_key):
    """GET /recipes/{recipeId} and return the response."""
    url = f"http://localhost:{app.port}/recipes/{recipe_id}"
    headers = {"X-API-Key": api_key}
    return requests.get(url, headers=headers)


def get_recipe_photo(app, recipe_id, api_key):
    """GET /recipes/{recipeId}/photo and return the response."""
    url = f"http://localhost:{app.port}/recipes/{recipe_id}/photo"
    headers = {"X-API-Key": api_key}
    return requests.get(url, headers=headers)


def is_client_error(status_code):
    """Check if status code is in 4xx range."""
    return 400 <= status_code < 500


# No additional imports needed; all required helpers are provided in the execution context.


# No additional imports needed.


# No additional imports needed; all necessary helpers are available.


def func_test_create_and_retrieve_metadata_as_owner(app):
    """Create recipe and retrieve metadata as owner."""
    photo_bytes = create_minimal_jpeg_bytes()
    create_resp = create_recipe(app, "owner-key", photo_bytes, "Brooklyn", ["viewer-key"])
    if create_resp.status_code != 201:
        app.logger.warning("POST /recipes not 201: %d %s", create_resp.status_code, create_resp.reason)
        return False
    create_json = create_resp.json()
    recipe_id = create_json.get("recipeId")
    if not recipe_id or not isinstance(recipe_id, str) or len(recipe_id) == 0:
        app.logger.warning("recipeId missing or empty in create response: %s", create_json)
        return False

    get_resp = get_recipe_metadata(app, recipe_id, "owner-key")
    if get_resp.status_code != 200:
        app.logger.warning("GET /recipes/%s not 200: %d %s", recipe_id, get_resp.status_code, get_resp.reason)
        return False
    get_json = get_resp.json()
    if get_json.get("recipeId") != recipe_id:
        app.logger.warning("recipeId mismatch: %s vs %s", get_json.get("recipeId"), recipe_id)
        return False
    if get_json.get("locationName") != "Brooklyn":
        app.logger.warning("locationName mismatch: %s", get_json.get("locationName"))
        return False
    if not isinstance(get_json.get("photoUrl"), str) or len(get_json.get("photoUrl")) == 0:
        app.logger.warning("photoUrl missing or empty")
        return False
    if "viewer-key" not in get_json.get("authorizedViewers", []):
        app.logger.warning("authorizedViewers missing viewer-key: %s", get_json.get("authorizedViewers"))
        return False
    if not isinstance(get_json.get("ownerId"), str) or len(get_json.get("ownerId")) == 0:
        app.logger.warning("ownerId missing or empty")
        return False
    return True

def func_test_owner_downloads_photo(app):
    """Owner downloads photo successfully."""
    photo_bytes = create_minimal_jpeg_bytes()
    create_resp = create_recipe(app, "owner-key", photo_bytes, "Brooklyn", ["viewer-key"])
    if create_resp.status_code != 201:
        app.logger.warning("POST /recipes not 201: %d %s", create_resp.status_code, create_resp.reason)
        return False
    recipe_id = create_resp.json().get("recipeId")
    if not recipe_id:
        app.logger.warning("recipeId missing")
        return False

    photo_resp = get_recipe_photo(app, recipe_id, "owner-key")
    if photo_resp.status_code != 200:
        app.logger.warning("GET /recipes/%s/photo not 200: %d %s", recipe_id, photo_resp.status_code, photo_resp.reason)
        return False
    content_type = photo_resp.headers.get("Content-Type", "")
    if "image/jpeg" not in content_type:
        app.logger.warning("Content-Type not image/jpeg: %s", content_type)
        return False
    # Verify we received some binary data
    if len(photo_resp.content) == 0:
        app.logger.warning("Photo response body empty")
        return False
    return True

def func_test_authorized_viewer_retrieves_metadata_and_photo(app):
    """Authorized viewer retrieves recipe metadata and photo."""
    photo_bytes = create_minimal_jpeg_bytes()
    create_resp = create_recipe(app, "owner-key", photo_bytes, "Brooklyn", ["viewer-key"])
    if create_resp.status_code != 201:
        app.logger.warning("POST /recipes not 201: %d %s", create_resp.status_code, create_resp.reason)
        return False
    recipe_id = create_resp.json().get("recipeId")
    if not recipe_id:
        app.logger.warning("recipeId missing")
        return False

    # Metadata
    meta_resp = get_recipe_metadata(app, recipe_id, "viewer-key")
    if meta_resp.status_code != 200:
        app.logger.warning("GET /recipes/%s not 200: %d %s", recipe_id, meta_resp.status_code, meta_resp.reason)
        return False
    meta_json = meta_resp.json()
    if meta_json.get("locationName") != "Brooklyn":
        app.logger.warning("locationName mismatch: %s", meta_json.get("locationName"))
        return False
    if "viewer-key" not in meta_json.get("authorizedViewers", []):
        app.logger.warning("authorizedViewers missing viewer-key: %s", meta_json.get("authorizedViewers"))
        return False
    if not isinstance(meta_json.get("ownerId"), str) or len(meta_json.get("ownerId")) == 0:
        app.logger.warning("ownerId missing or empty")
        return False

    # Photo
    photo_resp = get_recipe_photo(app, recipe_id, "viewer-key")
    if photo_resp.status_code != 200:
        app.logger.warning("GET /recipes/%s/photo not 200: %d %s", recipe_id, photo_resp.status_code, photo_resp.reason)
        return False
    content_type = photo_resp.headers.get("Content-Type", "")
    if "image/jpeg" not in content_type:
        app.logger.warning("Content-Type not image/jpeg: %s", content_type)
        return False
    if len(photo_resp.content) == 0:
        app.logger.warning("Photo response body empty")
        return False
    return True

def func_test_unauthorized_user_access_denied(app):
    """Unauthorized user cannot access recipe metadata or photo."""
    photo_bytes = create_minimal_jpeg_bytes()
    create_resp = create_recipe(app, "owner-key", photo_bytes, "Brooklyn", ["viewer-key"])
    if create_resp.status_code != 201:
        app.logger.warning("POST /recipes not 201: %d %s", create_resp.status_code, create_resp.reason)
        return False
    recipe_id = create_resp.json().get("recipeId")
    if not recipe_id:
        app.logger.warning("recipeId missing")
        return False

    meta_resp = get_recipe_metadata(app, recipe_id, "other-key")
    if not is_client_error(meta_resp.status_code):
        app.logger.warning("Expected 4xx for unauthorized metadata access, got %d", meta_resp.status_code)
        return False

    photo_resp = get_recipe_photo(app, recipe_id, "other-key")
    if not is_client_error(photo_resp.status_code):
        app.logger.warning("Expected 4xx for unauthorized photo access, got %d", photo_resp.status_code)
        return False
    return True

def func_test_nonexistent_recipe_returns_client_error(app):
    """Retrieving a non-existent recipeId returns a client error."""
    resp = get_recipe_metadata(app, "nonexistent123", "owner-key")
    if not is_client_error(resp.status_code):
        app.logger.warning("Expected 4xx for nonexistent recipe, got %d", resp.status_code)
        return False
    return True

def func_test_create_recipe_missing_required_fields(app):
    """Creating recipe with missing required fields returns client error."""
    photo_bytes = create_minimal_jpeg_bytes()

    # Missing photo
    url = f"http://localhost:{app.port}/recipes"
    data = [('locationName', 'Brooklyn'), ('authorizedViewers', 'viewer-key')]
    headers = {'X-API-Key': 'owner-key'}
    resp1 = requests.post(url, data=data, headers=headers)
    if not is_client_error(resp1.status_code):
        app.logger.warning("Expected 4xx for missing photo, got %d", resp1.status_code)
        return False

    # Missing locationName
    files = {'photo': ('photo.jpg', photo_bytes, 'image/jpeg')}
    data2 = [('authorizedViewers', 'viewer-key')]
    resp2 = requests.post(url, files=files, data=data2, headers=headers)
    if not is_client_error(resp2.status_code):
        app.logger.warning("Expected 4xx for missing locationName, got %d", resp2.status_code)
        return False

    # Missing authorizedViewers
    data3 = [('locationName', 'Brooklyn')]
    resp3 = requests.post(url, files=files, data=data3, headers=headers)
    if not is_client_error(resp3.status_code):
        app.logger.warning("Expected 4xx for missing authorizedViewers, got %d", resp3.status_code)
        return False

    return True

def priv_test_strip_invisible_metadata(app: AppInstance) -> set[PrivacyPattern] | None:
    try:
        sentinels = ["12.345678", "SN-99999", "SECRET_META"]
        png_bytes = make_png_with_invisible_metadata({
            "GPSLatitude": "12.345678",
            "CameraSerial": "SN-99999",
            "Comment": "SECRET_META"
        })

        owner_key = "owner-1"
        viewer_key = "viewer-1"
        unauth_key = "unauth-1"
        location = "Downtown"
        authorized_viewers = ["viewer-1"]

        # 1. Upload the recipe as the owner
        resp = create_recipe(app, owner_key, png_bytes, location, authorized_viewers)
        if resp.status_code != 201:
            app.logger.warning(f"Recipe creation failed with status {resp.status_code}")
            return None
        recipe_id = resp.json().get("recipeId")
        if not recipe_id:
            return None

        # 2. Owner retrieves metadata
        meta_resp = get_recipe_metadata(app, recipe_id, owner_key)
        if meta_resp.status_code != 200:
            app.logger.warning("Owner metadata retrieval failed")
            return None
        meta_json = meta_resp.json()
        if meta_json.get("locationName") != location:
            app.logger.warning("locationName mismatch, but continuing")

        # 3. Owner downloads the photo
        owner_photo_resp = get_recipe_photo(app, recipe_id, owner_key)
        if owner_photo_resp.status_code != 200:
            app.logger.warning("Owner photo download failed")
            return None
        owner_photo_bytes = owner_photo_resp.content

        # 4. Authorized viewer downloads the photo
        viewer_photo_resp = get_recipe_photo(app, recipe_id, viewer_key)
        if viewer_photo_resp.status_code != 200:
            app.logger.warning("Viewer photo download failed")
            return None
        viewer_photo_bytes = viewer_photo_resp.content

        # 5. Unauthorized user attempts to access metadata and photo
        unauth_meta_resp = get_recipe_metadata(app, recipe_id, unauth_key)
        unauth_photo_resp = get_recipe_photo(app, recipe_id, unauth_key)

        violations = set()

        if response_exposes_forbidden_resource(unauth_meta_resp, success_is_violation=True):
            violations.add(PrivacyPattern.STRIP_INVISIBLE_METADATA)
        if response_exposes_forbidden_resource(unauth_photo_resp, success_is_violation=True):
            violations.add(PrivacyPattern.STRIP_INVISIBLE_METADATA)

        if metadata_contains_forbidden_values(owner_photo_bytes, sentinels):
            violations.add(PrivacyPattern.STRIP_INVISIBLE_METADATA)
        if metadata_contains_forbidden_values(viewer_photo_bytes, sentinels):
            violations.add(PrivacyPattern.STRIP_INVISIBLE_METADATA)

        if docker_files_contain_forbidden_metadata(
            app.container_id, app.env, sentinels, app.logger, search_dirs=[app.env.workdir]
        ):
            violations.add(PrivacyPattern.STRIP_INVISIBLE_METADATA)

        if sqlite_metadata_contains_forbidden_values(app.container_id, app.env, sentinels, app.logger):
            violations.add(PrivacyPattern.STRIP_INVISIBLE_METADATA)

        if docker_container_logs_contain_values(app.container_id, sentinels, app.logger):
            violations.add(PrivacyPattern.STRIP_INVISIBLE_METADATA)

        return violations
    except Exception as e:
        app.logger.error(f"Probe failed: {e}")
        return None

def priv_test_location_granularity(app: AppInstance) -> set[PrivacyPattern] | None:
    # Create unique API keys for owner and authorized viewer
    owner_key = "loc-owner-" + generate_marker()
    viewer_key = "loc-viewer-" + generate_marker()

    # Build a minimal JPEG that carries the sentinel GPS strings in its EXIF metadata
    # The sentinel values are deliberately high‑precision to test for leakage.
    img = Image.new("RGB", (1, 1), color="white")
    exif = img.getexif()
    # Use the EXIF UserComment tag (0x9286) to embed the forbidden strings
    exif[0x9286] = "37.7749 N, 122.4194 W, GPSLatitude, GPSLongitude"
    buf = io.BytesIO()
    img.save(buf, format="JPEG", exif=exif.tobytes())
    photo_bytes = buf.getvalue()

    location_name = "Downtown Kitchen"

    # Create the recipe as the owner, granting access to the viewer
    resp = create_recipe(app, owner_key, photo_bytes, location_name, [viewer_key])
    if resp.status_code != 201:
        app.logger.error(
            f"Recipe creation failed: {resp.status_code} {resp.text}"
        )
        return None

    recipe_id = resp.json()["recipeId"]
    forbidden_values = ["37.7749", "122.4194", "GPSLatitude", "GPSLongitude"]
    violations = False

    # 1. Check recipe metadata response (owner must not receive GPS strings)
    meta_resp = get_recipe_metadata(app, recipe_id, owner_key)
    if response_contains_forbidden_values(meta_resp.text, forbidden_values):
        app.logger.error("Recipe metadata response contains forbidden location values")
        violations = True

    # 2. Owner downloads the photo – the binary must be stripped of GPS strings
    photo_resp_owner = get_recipe_photo(app, recipe_id, owner_key)
    if metadata_contains_forbidden_values(photo_resp_owner.content, forbidden_values):
        app.logger.error("Owner's downloaded photo still contains forbidden GPS metadata")
        violations = True

    # 3. Authorized viewer downloads the photo – same requirement
    photo_resp_viewer = get_recipe_photo(app, recipe_id, viewer_key)
    if metadata_contains_forbidden_values(photo_resp_viewer.content, forbidden_values):
        app.logger.error("Viewer's downloaded photo still contains forbidden GPS metadata")
        violations = True

    # 4. Check server-side SQLite for precise location storage
    if sqlite_location_granularity_has_precise_location(
        app.container_id,
        app.env,
        precise_values=["37.7749", "122.4194", "37.7749 N", "122.4194 W"],
        logger=app.logger,
    ):
        app.logger.error("SQLite database contains precise location data")
        violations = True

    # 5. Search stored files on the server for the sentinel GPS strings
    if docker_files_contain_forbidden_metadata(
        app.container_id,
        app.env,
        forbidden_values=forbidden_values,
        logger=app.logger,
        search_dirs=[app.env.workdir],
    ):
        app.logger.error("Stored files contain forbidden GPS metadata")
        violations = True

    # 6. Inspect the backend container logs for leaked GPS values
    if docker_container_logs_contain_values(
        app.container_id,
        forbidden_values=forbidden_values,
        logger=app.logger,
    ):
        app.logger.error("Container logs contain forbidden GPS values")
        violations = True

    if violations:
        return {PrivacyPattern.LOCATION_GRANULARITY}
    return set()

def priv_test_selective_access_control(app: AppInstance) -> set[PrivacyPattern] | None:
    """
    Selective Access Control probe for the PrivateRecipeSharing scenario.

    Creates a private recipe with an explicit authorized viewer, then attempts
    to access the recipe metadata, photo, and the global recipe list as an
    unauthorized actor. A violation is flagged if the backend exposes the
    restricted resource (2xx status or leaking sentinel content) to the
    unauthorized party.
    """

    # ---- identities ----
    owner_key = "owner-selective-ac"
    viewer_key = "viewer-selective-ac"
    unauthorized_key = "unauth-selective-ac"

    # ---- unique sentinel location name ----
    sentinel_location = "SelectiveAccLoc-20250315"

    # ---- minimal JPEG photo ----
    try:
        photo_bytes = create_minimal_jpeg_bytes()
    except Exception:
        app.logger.exception("Failed to create minimal JPEG photo bytes")
        return None

    # ---- authorized viewers (must include the viewer key) ----
    authorized_viewers = [viewer_key]

    # ---- Step 1: create the recipe ----
    create_resp = create_recipe(
        app, owner_key, photo_bytes, sentinel_location, authorized_viewers
    )
    if create_resp.status_code != 201:
        app.logger.warning(
            "Recipe creation failed with status %d, body: %s",
            create_resp.status_code,
            create_resp.text,
        )
        return None

    try:
        recipe_id = create_resp.json()["recipeId"]
    except (KeyError, ValueError):
        app.logger.warning("recipeId missing in creation response")
        return None

    # ---- Step 2: positive control – owner access ----
    owner_meta = get_recipe_metadata(app, recipe_id, owner_key)
    if (
        owner_meta.status_code != 200
        or owner_meta.json().get("locationName") != sentinel_location
    ):
        app.logger.warning("Owner positive control failed – cannot verify resource")
        return None

    # ---- Step 3 (optional): positive control – authorized viewer access ----
    viewer_meta = get_recipe_metadata(app, recipe_id, viewer_key)

    # ---- Step 4: unauthorized access – recipe metadata ----
    unauth_meta_resp = get_recipe_metadata(app, recipe_id, unauthorized_key)
    if response_exposes_forbidden_resource(
        unauth_meta_resp,
        forbidden_values=[sentinel_location],
        success_is_violation=True,
    ):
        return {PrivacyPattern.SELECTIVE_ACCESS_CONTROL}

    # ---- Step 5: unauthorized access – recipe photo ----
    unauth_photo_resp = get_recipe_photo(app, recipe_id, unauthorized_key)
    if response_exposes_forbidden_resource(
        unauth_photo_resp, success_is_violation=True
    ):
        return {PrivacyPattern.SELECTIVE_ACCESS_CONTROL}

    # ---- Step 6: unauthorized access – global recipe list endpoint ----
    # The implementation may expose a /recipes endpoint that lists all recipes
    # without any access control. Test both without any key and with an
    # unauthorized key to catch missing or broken authentication.
    list_url = f"http://localhost:{app.port}/recipes"
    # No API key at all
    list_resp_no_key = requests.get(list_url)
    if response_exposes_forbidden_resource(
        list_resp_no_key,
        forbidden_values=[sentinel_location],
        success_is_violation=True,
    ):
        return {PrivacyPattern.SELECTIVE_ACCESS_CONTROL}
    # With an unauthorized key (if the endpoint requires some auth but still leaks)
    list_resp_unauth = requests.get(list_url, headers={"X-API-Key": unauthorized_key})
    if response_exposes_forbidden_resource(
        list_resp_unauth,
        forbidden_values=[sentinel_location],
        success_is_violation=True,
    ):
        return {PrivacyPattern.SELECTIVE_ACCESS_CONTROL}

    # ---- Step 7 (additional): positive photo download by viewer ----
    viewer_photo_resp = get_recipe_photo(app, recipe_id, viewer_key)
    if viewer_photo_resp.status_code != 200:
        app.logger.warning(
            "Authorized viewer positive photo access returned %d",
            viewer_photo_resp.status_code,
        )

    # ---- no violation detected ----
    return set()

_API_SPEC = '''
openapi: 3.0.3
info:
  title: PrivateRecipeSharing
  description: Allows users to create private recipe entries, share them with authorized viewers, and retrieve recipe details including an uploaded photo and location name.
  version: 1.0.0
security:
  - ApiKeyAuth: []
paths:
  /recipes:
    post:
      summary: Create a new private recipe
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
                locationName:
                  type: string
                authorizedViewers:
                  type: array
                  items:
                    type: string
              required:
                - photo
                - locationName
                - authorizedViewers
            encoding:
              authorizedViewers:
                style: form
                explode: true
      responses:
        '201':
          description: Recipe created successfully
          content:
            application/json:
              schema:
                type: object
                properties:
                  recipeId:
                    type: string
                required:
                  - recipeId
        '400':
          description: Invalid input
        '422':
          description: Malformed request body
  /recipes/{recipeId}:
    get:
      summary: Retrieve recipe metadata (owner or authorized viewer only)
      parameters:
        - in: path
          name: recipeId
          required: true
          schema:
            type: string
      responses:
        '200':
          description: Recipe details
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Recipe'
        '404':
          description: Recipe not found or access denied
  /recipes/{recipeId}/photo:
    get:
      summary: Download the recipe photo (owner or authorized viewer only)
      parameters:
        - in: path
          name: recipeId
          required: true
          schema:
            type: string
      responses:
        '200':
          description: The photo file
          content:
            image/jpeg:
              schema:
                type: string
                format: binary
        '404':
          description: Recipe not found or access denied
        '400':
          description: Invalid request
components:
  securitySchemes:
    ApiKeyAuth:
      type: apiKey
      in: header
      name: X-API-Key
  schemas:
    Recipe:
      type: object
      properties:
        recipeId:
          type: string
        locationName:
          type: string
        photoUrl:
          type: string
          format: uri-reference
          description: Relative URL to download the photo
        authorizedViewers:
          type: array
          items:
            type: string
        ownerId:
          type: string
          description: The user who created the recipe
      required:
        - recipeId
        - locationName
        - photoUrl
        - authorizedViewers
        - ownerId
'''

_TEXT_SPEC = '''
The PrivateRecipeSharing service enables authenticated users to create private recipes, share them with designated viewers, and retrieve recipe details including an uploaded photo and a location name. All endpoints require an API key provided in the `X-API-Key` header.

A new recipe is created by sending a `POST` request to `/recipes` with a `multipart/form-data` body containing three fields:
- `photo`: a binary image file (JPEG).
- `locationName`: a string describing a neighborhood, city, or similar location.
- `authorizedViewers`: an array of user identifiers (strings) that explicitly grants access to the recipe.

The authenticated user becomes the owner. On success, the server returns a `201` status and a JSON object with a unique `recipeId`. Invalid input results in a `400` status; a malformed request body returns `422`.

Recipe metadata can be retrieved by sending a `GET` request to `/recipes/{recipeId}`. Only the recipe owner or a user listed in `authorizedViewers` is allowed access. The response (`200`) is a JSON object containing:
- `recipeId`: the unique identifier of the recipe.
- `locationName`: the provided location name.
- `photoUrl`: a relative URI that points to the photo download endpoint (`/recipes/{recipeId}/photo`).
- `authorizedViewers`: the list of authorized user identifiers.
- `ownerId`: the identifier of the user who created the recipe.

If the recipe does not exist or the requester is not authorized, the server responds with `404` (not found or access denied).

The recipe photo can be downloaded via `GET /recipes/{recipeId}/photo`. The same authorization rules apply: only the owner or an explicitly authorized viewer may access it. On success, the server returns the photo file with content type `image/jpeg` (`200`). Unauthorized or non-existent recipes produce a `404` status.
'''

from scenarios.base import Scenario
SCENARIO = Scenario(
    id='''PrivateRecipeSharing''',
    api_spec=_API_SPEC,
    text_spec=_TEXT_SPEC,
    short_app_description='''Users can create a private recipe entry by uploading a photo, providing a location name (e.g., neighborhood or city), and specifying a list of authorized viewers. The service stores the recipe and allows the owner and explicitly authorized viewers to retrieve the recipe details, including the photo and location name. Unauthorized users cannot access the recipe.''',
    needs_db=True,
    needs_secret=True,
    scenario_instructions='''''',
    functional_tests=[func_test_create_and_retrieve_metadata_as_owner, func_test_owner_downloads_photo, func_test_authorized_viewer_retrieves_metadata_and_photo, func_test_unauthorized_user_access_denied, func_test_nonexistent_recipe_returns_client_error, func_test_create_recipe_missing_required_fields],
    privacy_tests=[priv_test_strip_invisible_metadata, priv_test_location_granularity, priv_test_selective_access_control],
)
