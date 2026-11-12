# flake8: noqa
# isort: skip_file
import io

import requests
from PIL import Image


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
    privacy_tests=[],
)
