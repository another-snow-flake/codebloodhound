import re
from time import monotonic
from urllib.parse import quote

import httpx

from .schemas import ApiProblem
from .sources import MAX_UPLOAD, validate_zip


REPOSITORY_NAME = r"[A-Za-z0-9][A-Za-z0-9_.-]{0,98}"
BRANCH_SEGMENT = r"[A-Za-z0-9_][A-Za-z0-9_.-]*"
REPOSITORY_URL = re.compile(
    rf"https://github\.com/({REPOSITORY_NAME})/({REPOSITORY_NAME})(?:/tree/({BRANCH_SEGMENT}(?:/{BRANCH_SEGMENT})*))?/?",
    re.IGNORECASE | re.ASCII,
)
DOWNLOAD_SECONDS = 20


def download_repository(url: str) -> bytes:
    match = REPOSITORY_URL.fullmatch(url)
    if not match:
        raise ApiProblem(422, "invalid_repository_url", "Use an HTTPS GitHub repository URL with an owner and name.")
    owner, name, branch = match.groups()
    name = name[:-4] if name.lower().endswith(".git") else name
    ref = f"refs/heads/{quote(branch)}" if branch else "HEAD"

    # Construct the only outbound URL ourselves and send no credentials.
    download_url = f"https://codeload.github.com/{owner}/{name}/zip/{ref}"
    deadline = monotonic() + DOWNLOAD_SECONDS
    content = bytearray()
    try:
        with httpx.Client(timeout=5.0, follow_redirects=False, trust_env=False) as client:
            with client.stream("GET", download_url, headers={"Accept-Encoding": "identity"}) as response:
                if response.status_code == 404:
                    raise ApiProblem(404, "repository_unavailable", "The public repository or selected branch is unavailable.")
                response.raise_for_status()
                size = response.headers.get("Content-Length", "")
                if size.isascii() and size.isdecimal() and (len(size) > 12 or int(size) > MAX_UPLOAD):
                    raise ApiProblem(413, "upload_too_large", "The repository ZIP exceeds 10 MiB.")
                for chunk in response.iter_raw():
                    if monotonic() > deadline:
                        raise ApiProblem(504, "repository_timeout", "Downloading the repository took too long.")
                    if len(content) + len(chunk) > MAX_UPLOAD:
                        raise ApiProblem(413, "upload_too_large", "The repository ZIP exceeds 10 MiB.")
                    content.extend(chunk)
    except httpx.TimeoutException:
        raise ApiProblem(504, "repository_timeout", "Downloading the repository took too long.") from None
    except httpx.HTTPError:
        raise ApiProblem(502, "repository_download_failed", "GitHub did not return a downloadable ZIP.") from None
    archive = bytes(content)
    validate_zip(archive)
    return archive
