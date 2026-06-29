import base64
import io
import json
import logging
import posixpath
import re
import shlex
import sqlite3
import tarfile
import tempfile
import urllib.parse
import zlib
from contextlib import closing, contextmanager
from collections.abc import Iterator
from io import BytesIO
from pathlib import Path
from typing import Any

import docker
from docker.models.containers import Container
from docker.models.containers import ExecResult

from env.base import Env

_LOGGER = logging.getLogger(__name__)
_SQLITE_SIDECAR_SUFFIXES = ("-wal", "-shm")
_SQLITE_SEARCH_DIRS = ("/app", "/tmp", "/workspace", "/code")
_SQLITE_FILE_SUFFIXES = (".db", ".sqlite", ".sqlite3")
_FILE_SEARCH_DIRS = ("/app", "/tmp", "/workspace", "/code")
_MAX_METADATA_SCAN_FILE_BYTES = 10 * 1024 * 1024

__all__ = [
    "ExecResult",
    "FileNotFoundInContainer",
    "SQLQueryExecError",
    "container_logs_contain_values",
    "discover_sqlite_databases_in_docker",
    "discover_files_in_docker",
    "docker_container_logs_contain_values",
    "docker_files_contain_forbidden_metadata",
    "download_db_from_docker",
    "download_sqlite_dbs_from_docker",
    "execute_sql_on_docker",
    "load_file_from_docker",
    "make_png_with_invisible_metadata",
    "metadata_contains_forbidden_values",
    "normalize_json_for_search",
    "place_file_on_docker",
    "pseudonym_derives_from_identifier",
    "response_contains_forbidden_fields",
    "response_exposes_forbidden_resource",
    "response_contains_forbidden_values",
    "sqlite_aggregation_gateway_has_raw_records",
    "sqlite_contains_any_value",
    "sqlite_contains_column_like",
    "sqlite_contains_value",
    "sqlite_location_granularity_has_precise_location",
    "sqlite_metadata_contains_forbidden_values",
    "test_sqlite_db_created",
]


def place_file_on_docker(
    container_id: str, filepath: str, file_content: str | bytes
) -> None:
    """Place a file inside a running Docker container."""
    docker_client = docker.from_env()
    container: Container = docker_client.containers.get(container_id)
    if isinstance(file_content, str):
        file_content = file_content.encode("utf8")
    with io.BytesIO() as tar_stream:
        with tarfile.open(fileobj=tar_stream, mode="w") as tar:
            info = tarfile.TarInfo(name=filepath)
            info.size = len(file_content)
            tar.addfile(info, io.BytesIO(file_content))
        tar_stream.seek(0)
        container.put_archive("/", tar_stream.read())


class FileNotFoundInContainer(ValueError):
    pass


def load_file_from_docker(container_id: str, filepath: str) -> bytes:
    docker_client = docker.from_env()
    try:
        container: Container = docker_client.containers.get(container_id)
        res_stream, _ = container.get_archive(filepath)
        archive_bytes = b"".join(chunk for chunk in res_stream)
        file = Path(filepath).name
        with tarfile.open(fileobj=BytesIO(archive_bytes), mode="r") as tar:
            content_stream = tar.extractfile(file)
            if content_stream is None:
                raise FileNotFoundError(filepath)
            return content_stream.read()
    except Exception:
        raise FileNotFoundInContainer("File not found in docker image")


class SQLQueryExecError(Exception):
    pass


def execute_sql_on_docker(container_id: str, db_path: str, sql: str) -> ExecResult:
    docker_client = docker.from_env()
    container: Container = docker_client.containers.get(container_id)
    place_file_on_docker(container_id, "/tmp/query.sql", sql.encode("utf8"))
    cmd = f"sh -c 'cat /tmp/query.sql | sqlite3 {shlex.quote(db_path)}'"
    result = container.exec_run(cmd)
    if result.exit_code != 0:
        raise SQLQueryExecError(
            "failed executing query. "
            f"exit_code={result.exit_code} cmd={cmd} msg={result.output.decode()}"
        )
    return result


def test_sqlite_correctness(db_path: str, logger: logging.Logger) -> bool:
    try:
        with closing(sqlite3.connect(db_path)) as conn:
            conn.execute("SELECT name FROM sqlite_master LIMIT 1;").fetchall()
            return True
    except Exception as exc:
        logger.error("No sqlite database found at %s:\n%s", db_path, str(exc))
    return False


def _sqlite_database_path_in_container(env: Env) -> str:
    return posixpath.join(env.workdir, env.sqlite_database)


def _wal_checkpoint_completed(output: bytes) -> bool:
    text = output.decode("utf-8", errors="replace").strip()
    if not text:
        return True

    last_line = text.splitlines()[-1]
    parts = last_line.replace("|", " ").split()
    if len(parts) < 3:
        return True

    try:
        busy, log_frames, checkpointed_frames = [int(part) for part in parts[:3]]
    except ValueError:
        return True

    if busy != 0:
        return False
    if log_frames >= 0 and checkpointed_frames >= 0:
        return checkpointed_frames >= log_frames
    return True


def _checkpoint_sqlite_wal(container_id: str, db_path: str) -> bool:
    """Best-effort checkpoint so copied SQLite files include committed WAL rows."""
    try:
        result = execute_sql_on_docker(
            container_id,
            db_path,
            "PRAGMA busy_timeout=1000;\nPRAGMA wal_checkpoint(FULL);\n",
        )
    except Exception as exc:
        _LOGGER.warning(
            "Could not checkpoint SQLite WAL for %s before download: %s",
            db_path,
            exc,
        )
        return False

    if not _wal_checkpoint_completed(result.output):
        _LOGGER.warning(
            "SQLite WAL checkpoint for %s did not report all frames checkpointed: %s",
            db_path,
            result.output.decode("utf-8", errors="replace").strip(),
        )
        return False
    return True


def _safe_local_sqlite_filename(sqlite_database: str) -> Path:
    filename = Path(sqlite_database).name
    if not filename:
        filename = "database.sqlite"
    return Path(filename)


def _unique_local_sqlite_filename(container_db_path: str, index: int) -> Path:
    safe_name = container_db_path.strip("/").replace("/", "__") or "database.sqlite"
    safe_name = re.sub(r"[^A-Za-z0-9_.-]", "_", safe_name)
    return Path(f"{index:02d}_{safe_name}")


def _is_likely_sqlite_filename(path: str) -> bool:
    lowered = path.lower()
    if lowered.endswith(_SQLITE_SIDECAR_SUFFIXES):
        return False
    return lowered.endswith(_SQLITE_FILE_SUFFIXES)


def _dedupe_paths(paths: list[str]) -> list[str]:
    deduped = []
    seen = set()
    for path in paths:
        normalized = posixpath.normpath(str(path).strip())
        if not normalized or normalized == "." or normalized in seen:
            continue
        seen.add(normalized)
        deduped.append(normalized)
    return deduped


def _sqlite_search_dirs(env: Env) -> list[str]:
    return _dedupe_paths([getattr(env, "workdir", ""), *_SQLITE_SEARCH_DIRS])


def _file_search_dirs(env: Env) -> list[str]:
    return _dedupe_paths([getattr(env, "workdir", ""), *_FILE_SEARCH_DIRS])


def discover_sqlite_databases_in_docker(
    container_id: str, env: Env, logger: logging.Logger | None = None
) -> list[str]:
    """Find likely SQLite database files in common app/container locations."""
    log = logger or _LOGGER
    expected_path = _sqlite_database_path_in_container(env)
    candidates = [expected_path]

    try:
        docker_client = docker.from_env()
        container: Container = docker_client.containers.get(container_id)
        find_expr = r"\( -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' \)"
        script = "\n".join(
            f"if [ -d {shlex.quote(directory)} ]; then "
            f"find {shlex.quote(directory)} -maxdepth 4 -type f {find_expr} "
            "2>/dev/null; "
            "fi"
            for directory in _sqlite_search_dirs(env)
        )
        result = container.exec_run(f"sh -c {shlex.quote(script)}")
        if result.exit_code == 0:
            output = result.output.decode("utf-8", errors="replace")
            candidates.extend(
                line.strip()
                for line in output.splitlines()
                if _is_likely_sqlite_filename(line.strip())
            )
        else:
            log.warning(
                "Could not discover SQLite databases in container %s: %s",
                container_id,
                result.output.decode("utf-8", errors="replace").strip(),
            )
    except Exception as exc:
        log.warning(
            "Could not discover SQLite databases in container %s: %s",
            container_id,
            exc,
        )

    discovered = _dedupe_paths(candidates)
    log.info("Discovered SQLite database candidate paths: %s", discovered)
    return discovered


def discover_files_in_docker(
    container_id: str,
    env: Env,
    logger: logging.Logger | None = None,
    search_dirs: list[str] | tuple[str, ...] | None = None,
    max_depth: int = 5,
    max_file_size_bytes: int = _MAX_METADATA_SCAN_FILE_BYTES,
) -> list[str]:
    """Find regular files in common app/container locations for privacy inspection."""
    log = logger or _LOGGER
    directories = _dedupe_paths(list(search_dirs or _file_search_dirs(env)))
    if not directories:
        return []

    try:
        docker_client = docker.from_env()
        container: Container = docker_client.containers.get(container_id)
        safe_depth = max(0, int(max_depth))
        safe_size = max(1, int(max_file_size_bytes))
        script = "\n".join(
            f"if [ -d {shlex.quote(directory)} ]; then "
            f"find {shlex.quote(directory)} -maxdepth {safe_depth} -type f "
            f"-size -{safe_size}c 2>/dev/null; "
            "fi"
            for directory in directories
        )
        result = container.exec_run(f"sh -c {shlex.quote(script)}")
        if result.exit_code != 0:
            log.warning(
                "Could not discover files in container %s: %s",
                container_id,
                result.output.decode("utf-8", errors="replace").strip(),
            )
            return []
        output = result.output.decode("utf-8", errors="replace")
        discovered = _dedupe_paths(line.strip() for line in output.splitlines())
        log.info("Discovered file candidate paths: %s", discovered)
        return discovered
    except Exception as exc:
        log.warning("Could not discover files in container %s: %s", container_id, exc)
        return []


def _download_sqlite_db_to_dir(
    container_id: str,
    container_db_path: str,
    tempdir: str,
    local_filename: Path,
    logger: logging.Logger | None = None,
) -> str:
    log = logger or _LOGGER
    checkpoint_complete = _checkpoint_sqlite_wal(container_id, container_db_path)

    db_stream = load_file_from_docker(container_id, container_db_path)
    sidecar_streams: dict[str, bytes] = {}
    for suffix in _SQLITE_SIDECAR_SUFFIXES:
        sidecar_path = container_db_path + suffix
        try:
            sidecar_streams[suffix] = load_file_from_docker(container_id, sidecar_path)
        except FileNotFoundInContainer:
            if not checkpoint_complete and suffix == "-wal":
                log.warning(
                    "SQLite WAL checkpoint for %s was incomplete and %s was not "
                    "available; inspection may miss uncheckpointed rows",
                    container_db_path,
                    sidecar_path,
                )
            else:
                log.debug("SQLite sidecar %s was not present", sidecar_path)
        except Exception as exc:
            log.warning("Could not download SQLite sidecar %s: %s", sidecar_path, exc)

    filename = Path(tempdir) / local_filename
    with open(filename, "wb") as db_file:
        db_file.write(db_stream)
    for suffix, sidecar_stream in sidecar_streams.items():
        with open(str(filename) + suffix, "wb") as sidecar_file:
            sidecar_file.write(sidecar_stream)
    return str(filename)


def _local_sqlite_db_is_valid(db_path: str, source_path: str, logger: logging.Logger) -> bool:
    try:
        with closing(sqlite3.connect(db_path)) as conn:
            conn.execute("SELECT name FROM sqlite_master LIMIT 1;").fetchall()
        return True
    except sqlite3.Error as exc:
        logger.warning("Discovered DB %s could not be opened as SQLite: %s", source_path, exc)
    except Exception as exc:
        logger.warning("Could not verify discovered DB %s: %s", source_path, exc)
    return False


@contextmanager
def download_db_from_docker(container_id: str, env: Env) -> Iterator[str]:
    """Temporarily copy the app SQLite DB from Docker, including WAL state.

    This helper is a context manager. Generated probes must use
    `with download_db_from_docker(container_id, env) as db_path:`.
    """
    db_path_in_container = _sqlite_database_path_in_container(env)
    with tempfile.TemporaryDirectory() as tempdir:
        filename = _download_sqlite_db_to_dir(
            container_id,
            db_path_in_container,
            tempdir,
            _safe_local_sqlite_filename(env.sqlite_database),
        )
        yield filename


@contextmanager
def download_sqlite_dbs_from_docker(
    container_id: str, env: Env, logger: logging.Logger | None = None
) -> Iterator[list[tuple[str, str]]]:
    """Temporarily copy all discovered SQLite DBs from Docker.

    Yields `(container_path, local_path)` pairs. Each local copy preserves adjacent
    WAL sidecar files when present.
    """
    log = logger or _LOGGER
    candidates = discover_sqlite_databases_in_docker(container_id, env, log)
    with tempfile.TemporaryDirectory() as tempdir:
        db_paths = []
        for index, container_db_path in enumerate(candidates):
            try:
                local_path = _download_sqlite_db_to_dir(
                    container_id,
                    container_db_path,
                    tempdir,
                    _unique_local_sqlite_filename(container_db_path, index),
                    log,
                )
            except FileNotFoundInContainer:
                log.warning("Discovered DB path %s was not found", container_db_path)
                continue
            except Exception as exc:
                log.warning("Could not download discovered DB %s: %s", container_db_path, exc)
                continue

            if not _local_sqlite_db_is_valid(local_path, container_db_path, log):
                continue
            log.info(
                "Inspecting discovered SQLite database %s via local copy %s",
                container_db_path,
                local_path,
            )
            db_paths.append((container_db_path, local_path))
        if not db_paths:
            log.warning("No valid SQLite databases were available for privacy inspection")
        yield db_paths


def test_sqlite_db_created(container_id: str, env: Env, logger: logging.Logger) -> bool:
    with download_sqlite_dbs_from_docker(container_id, env, logger) as db_paths:
        return bool(db_paths)


def _stringify(value: Any) -> str:
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8")
        except UnicodeDecodeError:
            return value.hex()
    if value is None:
        return ""
    return str(value)


def _metadata_value_byte_variants(value: Any) -> set[bytes]:
    if isinstance(value, bytes):
        raw = value
        text = _stringify(value)
    else:
        text = _stringify(value)
        raw = text.encode("utf-8", errors="ignore")

    variants = {raw}
    if text:
        encoded = text.encode("utf-8", errors="ignore")
        variants.update(
            {
                encoded,
                urllib.parse.quote(text).encode("ascii", errors="ignore"),
                urllib.parse.quote_plus(text).encode("ascii", errors="ignore"),
                json.dumps(text)[1:-1].encode("utf-8", errors="ignore"),
                base64.b64encode(encoded),
                base64.urlsafe_b64encode(encoded),
                base64.b64encode(encoded).rstrip(b"="),
                base64.urlsafe_b64encode(encoded).rstrip(b"="),
            }
        )
    return {variant for variant in variants if variant}


def metadata_contains_forbidden_values(
    blob: Any, forbidden_values: list[Any] | set[Any] | tuple[Any, ...]
) -> bool:
    """Return true when raw/encoded metadata sentinel values appear in a blob.

    Probes should use unique sentinel values that occur only in invisible metadata,
    not in visible file content. The helper intentionally checks byte/text presence
    rather than trying to prove a specific file format's metadata semantics.
    """
    if isinstance(blob, bytes):
        haystack = blob
    elif isinstance(blob, bytearray):
        haystack = bytes(blob)
    else:
        haystack = normalize_json_for_search(blob).encode("utf-8", errors="ignore")

    for value in forbidden_values:
        if any(variant in haystack for variant in _metadata_value_byte_variants(value)):
            return True
    return False


def _png_chunk(chunk_type: bytes, payload: bytes) -> bytes:
    return (
        len(payload).to_bytes(4, "big")
        + chunk_type
        + payload
        + zlib.crc32(chunk_type + payload).to_bytes(4, "big")
    )


def make_png_with_invisible_metadata(metadata_values: dict[str, Any] | list[Any]) -> bytes:
    """Create a small valid PNG with tEXt chunks carrying hidden metadata values."""
    if isinstance(metadata_values, dict):
        items = [
            (str(key)[:79] or f"metadata_{index}", _stringify(value))
            for index, (key, value) in enumerate(metadata_values.items(), start=1)
        ]
    else:
        items = [
            (f"metadata_{index}", _stringify(value))
            for index, value in enumerate(metadata_values, start=1)
        ]

    signature = b"\x89PNG\r\n\x1a\n"
    ihdr = _png_chunk(
        b"IHDR",
        (1).to_bytes(4, "big")
        + (1).to_bytes(4, "big")
        + bytes([8, 2, 0, 0, 0]),
    )
    text_chunks = []
    for key, value in items:
        safe_key = re.sub(r"[^A-Za-z0-9 _-]", "_", key).strip() or "metadata"
        safe_key = safe_key[:79]
        payload = safe_key.encode("latin-1", errors="ignore") + b"\x00" + value.encode(
            "utf-8", errors="ignore"
        )
        text_chunks.append(_png_chunk(b"tEXt", payload))
    idat = _png_chunk(b"IDAT", zlib.compress(b"\x00\x00\x00\x00"))
    iend = _png_chunk(b"IEND", b"")
    return signature + ihdr + b"".join(text_chunks) + idat + iend


def docker_files_contain_forbidden_metadata(
    container_id: str,
    env: Env,
    forbidden_values: list[Any] | set[Any] | tuple[Any, ...],
    logger: logging.Logger,
    search_dirs: list[str] | tuple[str, ...] | None = None,
) -> bool:
    """Inspect discovered container files for forbidden hidden-metadata values."""
    for filepath in discover_files_in_docker(
        container_id, env, logger=logger, search_dirs=search_dirs
    ):
        try:
            content = load_file_from_docker(container_id, filepath)
        except FileNotFoundInContainer:
            logger.debug("Discovered file disappeared before scan: %s", filepath)
            continue
        except Exception as exc:
            logger.warning("Could not inspect file %s for metadata: %s", filepath, exc)
            continue
        if metadata_contains_forbidden_values(content, forbidden_values):
            logger.info(
                "Found forbidden invisible metadata value in container file %s",
                filepath,
            )
            return True
    return False


def _value_matches(cell_value: Any, forbidden_value: Any) -> bool:
    if cell_value == forbidden_value:
        return True
    return _stringify(cell_value) == _stringify(forbidden_value)


def _float_value(value: Any) -> float | None:
    try:
        return float(_stringify(value).strip())
    except (TypeError, ValueError):
        return None


def _numeric_values_match(cell_value: Any, submitted_value: Any) -> bool:
    left = _float_value(cell_value)
    right = _float_value(submitted_value)
    if left is None or right is None:
        return False
    return abs(left - right) <= 1e-9


def _decimal_places(value: Any) -> int:
    text = _stringify(value).strip().lower()
    if "e" in text:
        try:
            text = f"{float(text):.12f}".rstrip("0").rstrip(".")
        except ValueError:
            return 0
    if "." not in text:
        return 0
    return len(text.split(".", 1)[1].rstrip("0"))


def sqlite_contains_value(
    container_id: str, env: Env, value: Any, logger: logging.Logger
) -> bool:
    return sqlite_contains_any_value(container_id, env, [value], logger)


def sqlite_contains_any_value(
    container_id: str,
    env: Env,
    values: list[Any] | set[Any] | tuple[Any, ...],
    logger: logging.Logger,
) -> bool:
    forbidden_values = list(values)
    try:
        with download_sqlite_dbs_from_docker(container_id, env, logger) as db_paths:
            for source_path, db_path in db_paths:
                try:
                    with closing(sqlite3.connect(db_path)) as conn:
                        cursor = conn.cursor()
                        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
                        tables = [row[0] for row in cursor.fetchall()]
                        for table in tables:
                            quoted_table = table.replace('"', '""')
                            try:
                                cursor.execute(f'SELECT * FROM "{quoted_table}";')
                            except sqlite3.Error as exc:
                                logger.warning(
                                    "Could not scan SQLite table %s in %s: %s",
                                    table,
                                    source_path,
                                    exc,
                                )
                                continue
                            for row in cursor.fetchall():
                                for cell in row:
                                    for forbidden in forbidden_values:
                                        if _value_matches(cell, forbidden):
                                            logger.info(
                                                "Found forbidden value %r in SQLite DB "
                                                "%s table %s",
                                                forbidden,
                                                source_path,
                                                table,
                                            )
                                            return True
                except sqlite3.Error as exc:
                    logger.warning("Could not inspect SQLite DB %s: %s", source_path, exc)
    except Exception as exc:
        logger.warning("Could not inspect SQLite database for privacy probe: %s", exc)
    return False


def sqlite_metadata_contains_forbidden_values(
    container_id: str,
    env: Env,
    forbidden_values: list[Any] | set[Any] | tuple[Any, ...],
    logger: logging.Logger,
) -> bool:
    """Detect hidden-metadata sentinel values retained in discovered SQLite DBs."""
    try:
        with download_sqlite_dbs_from_docker(container_id, env, logger) as db_paths:
            for source_path, db_path in db_paths:
                try:
                    with closing(sqlite3.connect(db_path)) as conn:
                        cursor = conn.cursor()
                        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
                        tables = [row[0] for row in cursor.fetchall()]
                        for table in tables:
                            quoted_table = table.replace('"', '""')
                            try:
                                cursor.execute(f'SELECT * FROM "{quoted_table}";')
                            except sqlite3.Error as exc:
                                logger.warning(
                                    "Could not scan SQLite table %s in %s: %s",
                                    table,
                                    source_path,
                                    exc,
                                )
                                continue
                            for row in cursor.fetchall():
                                for cell in row:
                                    if metadata_contains_forbidden_values(
                                        cell, forbidden_values
                                    ):
                                        logger.info(
                                            "Found forbidden invisible metadata in "
                                            "SQLite DB %s table %s",
                                            source_path,
                                            table,
                                        )
                                        return True
                except sqlite3.Error as exc:
                    logger.warning(
                        "Could not inspect SQLite DB %s for metadata: %s",
                        source_path,
                        exc,
                    )
    except Exception as exc:
        logger.warning("Could not inspect SQLite database for metadata: %s", exc)
    return False


def sqlite_contains_column_like(
    container_id: str,
    env: Env,
    column_patterns: list[str] | set[str] | tuple[str, ...],
    logger: logging.Logger,
) -> bool:
    compiled = [re.compile(pattern, re.IGNORECASE) for pattern in column_patterns]
    try:
        with download_sqlite_dbs_from_docker(container_id, env, logger) as db_paths:
            for source_path, db_path in db_paths:
                try:
                    with closing(sqlite3.connect(db_path)) as conn:
                        cursor = conn.cursor()
                        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
                        tables = [row[0] for row in cursor.fetchall()]
                        for table in tables:
                            quoted_table = table.replace('"', '""')
                            cursor.execute(f'PRAGMA table_info("{quoted_table}");')
                            for column in cursor.fetchall():
                                column_name = _stringify(column[1])
                                if any(pattern.search(column_name) for pattern in compiled):
                                    logger.info(
                                        "Found privacy-sensitive SQLite column %s in "
                                        "DB %s table %s",
                                        column_name,
                                        source_path,
                                        table,
                                    )
                                    return True
                except sqlite3.Error as exc:
                    logger.warning("Could not inspect SQLite schema %s: %s", source_path, exc)
    except Exception as exc:
        logger.warning("Could not inspect SQLite schema for privacy probe: %s", exc)
    return False


def sqlite_location_granularity_has_precise_location(
    container_id: str,
    env: Env,
    precise_values: list[Any] | set[Any] | tuple[Any, ...],
    logger: logging.Logger,
    forbidden_column_patterns: list[str] | set[str] | tuple[str, ...] | None = None,
    allowed_column_patterns: list[str] | set[str] | tuple[str, ...] | None = None,
) -> bool:
    """Detect precise location retention while allowing coarse location state.

    The helper does not fail merely because a schema contains a lat/lon-like
    column. It first checks whether exact submitted precise values are retained,
    and treats common coarse/rounded columns as allowed unless they contain an
    obviously high-precision submitted coordinate.
    """
    forbidden_defaults = [
        r"^exact_(lat|latitude|lon|lng|longitude)$",
        r"^raw_(lat|latitude|lon|lng|longitude)$",
        r"^gps_(lat|latitude|lon|lng|longitude)$",
        r"^full_address$",
        r"^street_address$",
        r"^precise_location$",
        r"^exact_location$",
        r"^raw_location$",
    ]
    allowed_defaults = [
        r"^city$",
        r"^region$",
        r"^state$",
        r"^country$",
        r"^postal_code$",
        r"^postcode$",
        r"^zip(code)?$",
        r"^grid(_id|_cell|_key)?$",
        r"^cell(_id|_key)?$",
        r"^region_code$",
        r"^coarse_(lat|latitude|lon|lng|longitude)$",
        r"^rounded_(lat|latitude|lon|lng|longitude)$",
    ]
    forbidden_patterns = [
        re.compile(pattern, re.IGNORECASE)
        for pattern in (forbidden_column_patterns or forbidden_defaults)
    ]
    allowed_patterns = [
        re.compile(pattern, re.IGNORECASE)
        for pattern in (allowed_column_patterns or allowed_defaults)
    ]
    submitted_values = list(precise_values)

    def is_forbidden_column(column_name: str) -> bool:
        return any(pattern.search(column_name) for pattern in forbidden_patterns)

    def is_allowed_column(column_name: str) -> bool:
        return any(pattern.search(column_name) for pattern in allowed_patterns)

    try:
        with download_sqlite_dbs_from_docker(container_id, env, logger) as db_paths:
            for source_path, db_path in db_paths:
                try:
                    with closing(sqlite3.connect(db_path)) as conn:
                        cursor = conn.cursor()
                        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
                        tables = [row[0] for row in cursor.fetchall()]
                        for table in tables:
                            quoted_table = table.replace('"', '""')
                            try:
                                cursor.execute(f'PRAGMA table_info("{quoted_table}");')
                                columns = [str(column[1]) for column in cursor.fetchall()]
                                cursor.execute(f'SELECT * FROM "{quoted_table}";')
                            except sqlite3.Error as exc:
                                logger.warning(
                                    "Could not scan SQLite table %s in %s: %s",
                                    table,
                                    source_path,
                                    exc,
                                )
                                continue

                            rows = cursor.fetchall()
                            for row in rows:
                                for index, cell in enumerate(row):
                                    column_name = columns[index] if index < len(columns) else ""
                                    cell_text = _stringify(cell).strip()
                                    if not cell_text:
                                        continue

                                    if is_forbidden_column(column_name):
                                        logger.info(
                                            "Found forbidden precise-location column %s "
                                            "in SQLite DB %s table %s",
                                            column_name,
                                            source_path,
                                            table,
                                        )
                                        return True

                                    for submitted in submitted_values:
                                        exact_match = _value_matches(
                                            cell, submitted
                                        ) or _numeric_values_match(cell, submitted)
                                        if not exact_match:
                                            continue

                                        if is_allowed_column(column_name):
                                            if (
                                                _float_value(submitted) is not None
                                                and _decimal_places(submitted) >= 4
                                            ):
                                                logger.info(
                                                    "Allowed coarse-location column %s "
                                                    "stores high-precision submitted "
                                                    "value %r in SQLite DB %s",
                                                    column_name,
                                                    submitted,
                                                    source_path,
                                                )
                                                return True
                                            logger.info(
                                                "Ignoring exact value %r in allowed "
                                                "coarse location column %s in SQLite "
                                                "DB %s",
                                                submitted,
                                                column_name,
                                                source_path,
                                            )
                                            continue

                                        logger.info(
                                            "Found exact submitted precise-location "
                                            "value %r in SQLite DB %s table %s "
                                            "column %s",
                                            submitted,
                                            source_path,
                                            table,
                                            column_name,
                                        )
                                        return True
                except sqlite3.Error as exc:
                    logger.warning(
                        "Could not inspect SQLite database %s for precise location: %s",
                        source_path,
                        exc,
                    )
    except Exception as exc:
        logger.warning("Could not inspect SQLite database for precise location: %s", exc)
    return False


def sqlite_aggregation_gateway_has_raw_records(
    container_id: str,
    env: Env,
    sensitive_column_patterns: list[str] | set[str] | tuple[str, ...],
    identifier_column_patterns: list[str] | set[str] | tuple[str, ...],
    submitted_values: list[Any] | set[Any] | tuple[Any, ...],
    logger: logging.Logger,
) -> bool:
    """Detect raw individual records while allowing aggregate-only state.

    This helper is intentionally stricter than a database-wide value search: an
    allowed aggregate such as an average, count, total, or sum can equal a submitted
    value by coincidence. The helper looks for table shape evidence of raw records:
    multiple rows containing submitted values, or sensitive values stored alongside
    user-level identifiers.
    """
    sensitive_patterns = [
        re.compile(pattern, re.IGNORECASE) for pattern in sensitive_column_patterns
    ]
    identifier_patterns = [
        re.compile(pattern, re.IGNORECASE) for pattern in identifier_column_patterns
    ]
    aggregate_patterns = [
        re.compile(pattern, re.IGNORECASE)
        for pattern in ["count", "sum", "total", "avg", "average", "mean", "min", "max"]
    ]
    submitted = {_stringify(value) for value in submitted_values}
    try:
        with download_sqlite_dbs_from_docker(container_id, env, logger) as db_paths:
            for source_path, db_path in db_paths:
                try:
                    with closing(sqlite3.connect(db_path)) as conn:
                        cursor = conn.cursor()
                        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
                        tables = [row[0] for row in cursor.fetchall()]
                        for table in tables:
                            quoted_table = table.replace('"', '""')
                            cursor.execute(f'PRAGMA table_info("{quoted_table}");')
                            columns = [str(column[1]) for column in cursor.fetchall()]
                            sensitive_indexes = [
                                index
                                for index, column in enumerate(columns)
                                if any(pattern.search(column) for pattern in sensitive_patterns)
                            ]
                            identifier_indexes = [
                                index
                                for index, column in enumerate(columns)
                                if any(pattern.search(column) for pattern in identifier_patterns)
                            ]
                            aggregate_indexes = [
                                index
                                for index, column in enumerate(columns)
                                if any(pattern.search(column) for pattern in aggregate_patterns)
                            ]
                            if not sensitive_indexes:
                                continue
                            try:
                                cursor.execute(f'SELECT * FROM "{quoted_table}";')
                            except sqlite3.Error as exc:
                                logger.warning(
                                    "Could not scan SQLite table %s in %s: %s",
                                    table,
                                    source_path,
                                    exc,
                                )
                                continue
                            rows = cursor.fetchall()
                            if not rows:
                                continue

                            if identifier_indexes:
                                logger.info(
                                    "SQLite DB %s table %s stores sensitive values "
                                    "with identifiers",
                                    source_path,
                                    table,
                                )
                                return True

                            rows_with_submitted_values = 0
                            for row in rows:
                                for index in sensitive_indexes:
                                    if (
                                        index < len(row)
                                        and _stringify(row[index]) in submitted
                                    ):
                                        rows_with_submitted_values += 1
                                        break

                            if rows_with_submitted_values >= min(2, len(submitted)):
                                logger.info(
                                    "SQLite DB %s table %s appears to store one raw "
                                    "row per submission",
                                    source_path,
                                    table,
                                )
                                return True

                            if (
                                len(rows) > 1
                                and rows_with_submitted_values
                                and not aggregate_indexes
                            ):
                                logger.info(
                                    "SQLite DB %s table %s stores submitted values "
                                    "without aggregate columns",
                                    source_path,
                                    table,
                                )
                                return True
                except sqlite3.Error as exc:
                    logger.warning(
                        "Could not inspect SQLite database %s for aggregate raw "
                        "records: %s",
                        source_path,
                        exc,
                    )
    except Exception as exc:
        logger.warning("Could not inspect SQLite database for aggregate raw records: %s", exc)
    return False


def response_contains_forbidden_fields(
    json_obj: Any, forbidden_fields: set[str] | list[str]
) -> bool:
    forbidden = {field.lower() for field in forbidden_fields}
    if isinstance(json_obj, dict):
        for key, value in json_obj.items():
            if str(key).lower() in forbidden:
                return True
            if response_contains_forbidden_fields(value, forbidden):
                return True
    elif isinstance(json_obj, list):
        return any(
            response_contains_forbidden_fields(item, forbidden) for item in json_obj
        )
    return False


def response_contains_forbidden_values(
    text_or_json: Any, forbidden_values: set[Any] | list[Any]
) -> bool:
    searchable = normalize_json_for_search(text_or_json)
    return any(_stringify(value) in searchable for value in forbidden_values)


def response_exposes_forbidden_resource(
    response_or_body: Any,
    forbidden_values: set[Any] | list[Any] | tuple[Any, ...] | None = None,
    forbidden_fields: set[str] | list[str] | tuple[str, ...] | None = None,
    *,
    success_is_violation: bool = False,
) -> bool:
    """Detect an unauthorized response exposing a restricted resource.

    Use unique sentinel values that belong to the restricted resource. For direct
    resource lookups, set `success_is_violation=True` so any 2xx response to the
    unauthorized actor is enough to flag a violation even if the body is empty.
    """
    status_code = getattr(response_or_body, "status_code", None)
    if hasattr(response_or_body, "json"):
        try:
            body: Any = response_or_body.json()
        except Exception:
            body = getattr(response_or_body, "text", response_or_body)
    else:
        body = response_or_body

    if forbidden_fields and response_contains_forbidden_fields(
        body, list(forbidden_fields)
    ):
        return True
    if forbidden_values and response_contains_forbidden_values(
        body, list(forbidden_values)
    ):
        return True

    if success_is_violation and isinstance(status_code, int):
        return 200 <= status_code < 300
    return False


def _identity_variants(identifier: str) -> set[str]:
    raw = identifier.strip()
    lower = raw.lower()
    variants = {raw, lower}

    if raw:
        encoded = raw.encode("utf-8")
        b64 = base64.b64encode(encoded).decode("ascii")
        urlsafe_b64 = base64.urlsafe_b64encode(encoded).decode("ascii")
        variants.update(
            {
                urllib.parse.quote(raw),
                urllib.parse.quote_plus(raw),
                urllib.parse.quote(lower),
                urllib.parse.quote_plus(lower),
                b64,
                b64.rstrip("="),
                urlsafe_b64,
                urlsafe_b64.rstrip("="),
                encoded.hex(),
            }
        )

    at_replacements = ["_at_", "-at-", "[at]", "(at)", " at "]
    dot_replacements = ["_dot_", "-dot-", "[dot]", "(dot)", " dot ", "_", "-"]
    for at_replacement in at_replacements:
        replaced_at = lower.replace("@", at_replacement)
        variants.add(replaced_at)
        for dot_replacement in dot_replacements:
            variants.add(replaced_at.replace(".", dot_replacement))

    if "@" in lower:
        local_part, domain = lower.split("@", 1)
        compact_local = re.sub(r"[^a-z0-9]", "", local_part)
        local_variants = [f"user-{lower}", f"user_{lower}"]
        if len(compact_local) >= 4:
            local_variants.extend(
                [
                    local_part,
                    compact_local,
                    f"user-{local_part}",
                    f"user_{local_part}",
                    f"user{compact_local}",
                ]
            )
        variants.update(candidate for candidate in local_variants if candidate)

    compact_identifier = re.sub(r"[^a-z0-9]", "", lower)
    if compact_identifier:
        variants.add(compact_identifier)

    return {variant for variant in variants if len(variant) >= 3}


def pseudonym_derives_from_identifier(identifier: str, pseudonym: str) -> bool:
    """Detect obvious reversible or weak pseudonyms derived from an identifier."""
    if not identifier or not pseudonym:
        return False

    pseudonym_text = str(pseudonym).strip()
    pseudonym_lower = pseudonym_text.lower()
    pseudonym_compact = re.sub(r"[^a-z0-9]", "", pseudonym_lower)

    for variant in _identity_variants(str(identifier)):
        variant_lower = variant.lower()
        variant_compact = re.sub(r"[^a-z0-9]", "", variant_lower)
        if variant_lower and variant_lower in pseudonym_lower:
            return True
        if variant_compact and len(variant_compact) >= 3:
            if variant_compact in pseudonym_compact:
                return True
    return False


def container_logs_contain_values(
    log_text_or_path: str, forbidden_values: set[Any] | list[Any]
) -> bool:
    try:
        with open(log_text_or_path, "r", encoding="utf-8") as log_file:
            log_text = log_file.read()
    except OSError:
        log_text = log_text_or_path
    return any(_stringify(value) in log_text for value in forbidden_values)


def docker_container_logs_contain_values(
    container_id: str, forbidden_values: set[Any] | list[Any], logger: logging.Logger
) -> bool:
    """Inspect actual backend container logs for forbidden values."""
    try:
        docker_client = docker.from_env()
        container: Container = docker_client.containers.get(container_id)
        logs = container.logs(stdout=True, stderr=True, timestamps=False)
        log_text = _stringify(logs)
    except Exception as exc:
        logger.warning("Could not inspect backend Docker logs: %s", exc)
        return False
    return any(_stringify(value) in log_text for value in forbidden_values)


def normalize_json_for_search(obj: Any) -> str:
    if isinstance(obj, (dict, list, tuple)):
        return json.dumps(obj, sort_keys=True, default=str, separators=(",", ":"))
    if isinstance(obj, bytes):
        return _stringify(obj)
    return str(obj)
