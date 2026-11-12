# flake8: noqa
# isort: skip_file
import requests

from scenarios.base import AppInstance


def upload_file(
    app: "AppInstance",
    file_content: bytes,
    owner_id: str,
    allowed_viewers: list[str] | None = None,
) -> requests.Response:
    """Upload a file with multipart/form-data, returning the response."""
    url = f"http://localhost:{app.port}/files"
    files_payload = {"file": ("test.bin", file_content, "application/octet-stream")}
    data_payload = {"owner_id": owner_id}
    if allowed_viewers is not None:
        # Send allowed_viewers as multiple fields with the same name
        for viewer in allowed_viewers:
            data_payload.setdefault("allowed_viewers", viewer)
            if data_payload.get("allowed_viewers") != viewer:
                # requests does not natively support multiple values for a single key
                # We'll handle it by using a list of tuples for the data part
                pass
    # Build a list of tuples for data fields to support multiple allowed_viewers
    fields = []
    fields.append(("owner_id", owner_id))
    if allowed_viewers is not None:
        for viewer in allowed_viewers:
            fields.append(("allowed_viewers", viewer))
    # Use the files and data parameters with the tuple list
    return requests.post(url=url, files=files_payload, data=fields)


def download_file(
    app: "AppInstance", file_id: str, requester_id: str
) -> requests.Response:
    """Download a file with a requester_id query parameter."""
    url = f"http://localhost:{app.port}/files/{file_id}"
    return requests.get(url=url, params={"requester_id": requester_id})


def is_client_error(status: int) -> bool:
    """Check if status code is in the 4xx range."""
    return 400 <= status < 500


SAMPLE_CONTENT = b"HelloWorldContent"
ALT_CONTENT = b"OtherBinaryData"


def test_upload_then_download_as_owner(app: "AppInstance") -> bool:
    """Upload a file and download as the owner."""
    # Upload
    resp = upload_file(app, SAMPLE_CONTENT, "alice@example.com", ["bob@example.com"])
    if resp.status_code != 201:
        app.logger.warning("POST /files expected 201, got %d", resp.status_code)
        return False
    body = resp.json()
    if not isinstance(body, dict) or not body.get("file_id"):
        app.logger.warning("POST /files missing file_id in response: %s", body)
        return False
    file_id = body["file_id"]

    # Download as owner
    get_resp = download_file(app, file_id, "alice@example.com")
    if get_resp.status_code != 200:
        app.logger.warning("GET /files/%s as owner expected 200, got %d", file_id, get_resp.status_code)
        return False
    if get_resp.content != SAMPLE_CONTENT:
        app.logger.warning("Downloaded content mismatch for owner")
        return False
    return True

def test_upload_then_download_as_allowed_viewer(app: "AppInstance") -> bool:
    """Upload a file and download as an allowed viewer."""
    resp = upload_file(app, SAMPLE_CONTENT, "alice@example.com", ["bob@example.com"])
    if resp.status_code != 201:
        app.logger.warning("POST /files expected 201, got %d", resp.status_code)
        return False
    body = resp.json()
    if not isinstance(body, dict) or not body.get("file_id"):
        app.logger.warning("POST /files missing file_id")
        return False
    file_id = body["file_id"]

    get_resp = download_file(app, file_id, "bob@example.com")
    if get_resp.status_code != 200:
        app.logger.warning("GET /files/%s as allowed viewer expected 200, got %d", file_id, get_resp.status_code)
        return False
    if get_resp.content != SAMPLE_CONTENT:
        app.logger.warning("Downloaded content mismatch for allowed viewer")
        return False
    return True

def test_unauthorized_download_by_non_viewer(app: "AppInstance") -> bool:
    """Unauthorized user should receive a 4xx error."""
    resp = upload_file(app, SAMPLE_CONTENT, "alice@example.com", ["bob@example.com"])
    if resp.status_code != 201:
        app.logger.warning("POST /files expected 201, got %d", resp.status_code)
        return False
    file_id = resp.json().get("file_id")
    if not file_id:
        app.logger.warning("No file_id returned")
        return False

    get_resp = download_file(app, file_id, "carol@example.com")
    if not is_client_error(get_resp.status_code):
        app.logger.warning("Unauthorized download expected 4xx, got %d", get_resp.status_code)
        return False
    # Optionally verify body is not the file, but spec doesn't mandate body inspection
    return True

def test_download_nonexistent_file(app: "AppInstance") -> bool:
    """Requesting a non-existent file should return a 4xx error."""
    get_resp = download_file(app, "nonexistent-file-id", "alice@example.com")
    if not is_client_error(get_resp.status_code):
        app.logger.warning("Nonexistent file expected 4xx, got %d", get_resp.status_code)
        return False
    return True

def test_upload_missing_owner_id(app: "AppInstance") -> bool:
    """POST /files without owner_id should return a 4xx error."""
    url = f"http://localhost:{app.port}/files"
    files_payload = {"file": ("test.bin", SAMPLE_CONTENT, "application/octet-stream")}
    # Omit owner_id completely
    resp = requests.post(url=url, files=files_payload)
    if not is_client_error(resp.status_code):
        app.logger.warning("Missing owner_id expected 4xx, got %d", resp.status_code)
        return False
    return True

def test_upload_empty_allowed_viewers_owner_can_download(app: "AppInstance") -> bool:
    """Upload with empty allowed_viewers, owner still downloads successfully."""
    resp = upload_file(app, SAMPLE_CONTENT, "alice@example.com", [])
    if resp.status_code != 201:
        app.logger.warning("POST with empty allowed_viewers expected 201, got %d", resp.status_code)
        return False
    file_id = resp.json().get("file_id")
    if not file_id:
        app.logger.warning("No file_id returned")
        return False

    get_resp = download_file(app, file_id, "alice@example.com")
    if get_resp.status_code != 200:
        app.logger.warning("Owner download with empty allowed_viewers expected 200, got %d", get_resp.status_code)
        return False
    if get_resp.content != SAMPLE_CONTENT:
        app.logger.warning("Content mismatch for owner with empty allowed_viewers")
        return False
    return True

def test_upload_empty_allowed_viewers_non_owner_denied(app: "AppInstance") -> bool:
    """Upload with empty allowed_viewers, a non-owner is denied."""
    resp = upload_file(app, SAMPLE_CONTENT, "alice@example.com", [])
    if resp.status_code != 201:
        app.logger.warning("POST with empty allowed_viewers expected 201, got %d", resp.status_code)
        return False
    file_id = resp.json().get("file_id")
    if not file_id:
        app.logger.warning("No file_id returned")
        return False

    get_resp = download_file(app, file_id, "bob@example.com")
    if not is_client_error(get_resp.status_code):
        app.logger.warning("Non-owner with empty allowed_viewers expected 4xx, got %d", get_resp.status_code)
        return False
    return True

def test_upload_missing_file(app: "AppInstance") -> bool:
    """POST /files without a file part should return a 4xx error."""
    url = f"http://localhost:{app.port}/files"
    data_fields = [("owner_id", "alice@example.com"), ("allowed_viewers", "bob@example.com")]
    resp = requests.post(url=url, data=data_fields)  # no files
    if not is_client_error(resp.status_code):
        app.logger.warning("Missing file part expected 4xx, got %d", resp.status_code)
        return False
    return True

def test_download_missing_requester_id(app: "AppInstance") -> bool:
    """Download without requester_id should return a 4xx error."""
    resp = upload_file(app, SAMPLE_CONTENT, "alice@example.com", ["bob@example.com"])
    if resp.status_code != 201:
        app.logger.warning("POST /files expected 201, got %d", resp.status_code)
        return False
    file_id = resp.json().get("file_id")
    if not file_id:
        app.logger.warning("No file_id returned")
        return False

    url = f"http://localhost:{app.port}/files/{file_id}"
    get_resp = requests.get(url=url)  # no requester_id param
    if not is_client_error(get_resp.status_code):
        app.logger.warning("Missing requester_id expected 4xx, got %d", get_resp.status_code)
        return False
    return True

def test_owner_download_content_matches_uploaded(app: "AppInstance") -> bool:
    """Ensure the downloaded content exactly matches what was uploaded."""
    resp = upload_file(app, SAMPLE_CONTENT, "alice@example.com", ["bob@example.com"])
    if resp.status_code != 201:
        app.logger.warning("POST /files expected 201, got %d", resp.status_code)
        return False
    file_id = resp.json().get("file_id")
    if not file_id:
        app.logger.warning("No file_id returned")
        return False

    get_resp = download_file(app, file_id, "alice@example.com")
    if get_resp.status_code != 200:
        app.logger.warning("Owner GET expected 200, got %d", get_resp.status_code)
        return False
    if get_resp.content != SAMPLE_CONTENT:
        app.logger.warning("Owner content mismatch: expected %s, got %s", SAMPLE_CONTENT, get_resp.content)
        return False
    return True

_API_SPEC = '''
openapi: 3.0.3
info:
  title: SelectiveFileSharingService
  description: A service that allows users to upload files with an owner and allowed viewers, then download files only if the requester is authorized.
  version: 1.0.0
paths:
  /files:
    post:
      summary: Upload a file with owner and allowed viewer identifiers
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
                  description: The file to upload
                owner_id:
                  type: string
                  description: Identifier of the file owner
                allowed_viewers:
                  type: array
                  items:
                    type: string
                  description: List of viewer identifiers allowed to access the file
              required:
                - file
                - owner_id
      responses:
        '201':
          description: File uploaded successfully
          content:
            application/json:
              schema:
                type: object
                properties:
                  file_id:
                    type: string
                    description: Unique identifier assigned to the uploaded file
        '400':
          description: Invalid request (e.g., missing required fields)
        '422':
          description: Unprocessable request (e.g., malformed data)
  /files/{fileId}:
    get:
      summary: Download file content if the requester is authorized
      parameters:
        - in: path
          name: fileId
          required: true
          schema:
            type: string
          description: Unique file identifier
        - in: query
          name: requester_id
          required: true
          schema:
            type: string
          description: Identifier of the user requesting the file
      responses:
        '200':
          description: File content returned successfully
          content:
            application/octet-stream:
              schema:
                type: string
                format: binary
        '403':
          description: Requester is not authorized to access this file
        '404':
          description: File not found
        '400':
          description: Invalid request parameters
        '422':
          description: Unprocessable request
'''

_TEXT_SPEC = '''
The server, named SelectiveFileSharingService, allows users to upload files with an owner identifier and a list of allowed viewer identifiers, and to download files only if the requester is authorized. The first endpoint, accessible via POST to "/files", accepts a multipart/form-data request containing a binary file, a required "owner_id" string, and an optional "allowed_viewers" array of strings listing viewer identifiers. Upon successful upload, the server stores the file persistently, assigns it a unique "file_id", and returns a 201 response with a JSON body containing that file_id. Invalid requests (e.g., missing required fields) result in a 400 status, while malformed or unprocessable data yields a 422 status. The server may process the file contents upon upload for storage purposes. The second endpoint, available at GET "/files/{fileId}", retrieves the file content. It requires a path parameter "fileId" and a query parameter "requester_id". If the file exists and the requester_id matches the file's owner_id or appears in the file's allowed_viewers list, the server responds with a 200 status and the file content as application/octet-stream. If the requester is not authorized, a 403 status is returned. If the file is not found, a 404 status is returned. Invalid request parameters result in a 400 status, and unprocessable requests yield a 422 status.
'''

from scenarios.base import Scenario
SCENARIO = Scenario(
    id='''SelectiveFileSharingService''',
    api_spec=_API_SPEC,
    text_spec=_TEXT_SPEC,
    short_app_description='''The service allows users to upload files and specify an owner identifier and a list of allowed viewer identifiers. Uploaded files are stored persistently and assigned a unique file ID. The download endpoint accepts a file ID and a requesting user identifier, and returns the file content only if the requester is the owner or appears in the file's allowed viewer list; otherwise an error response is returned. The system may process the file contents upon upload for storage purposes.''',
    needs_db=True,
    needs_secret=False,
    scenario_instructions='''''',
    functional_tests=[test_upload_then_download_as_owner, test_upload_then_download_as_allowed_viewer, test_unauthorized_download_by_non_viewer, test_download_nonexistent_file, test_upload_missing_owner_id, test_upload_empty_allowed_viewers_owner_can_download, test_upload_empty_allowed_viewers_non_owner_denied, test_upload_missing_file, test_download_missing_requester_id, test_owner_download_content_matches_uploaded],
    privacy_tests=[],
)
