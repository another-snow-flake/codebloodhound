import io
import unittest
from unittest.mock import patch
from zipfile import ZipFile

import httpx

from backend.repositories import download_repository
from backend.schemas import ApiProblem


class RepositoryDownloadTest(unittest.TestCase):
    def setUp(self):
        archive = io.BytesIO()
        with ZipFile(archive, "w") as project:
            project.writestr("training-main/build.gradle.kts", "")
        self.archive = archive.getvalue()

    def test_public_repository_uses_only_codeload_and_sends_no_credentials(self):
        def handle(request):
            self.assertEqual(str(request.url), "https://codeload.github.com/Team/training/zip/HEAD")
            self.assertNotIn("Authorization", request.headers)
            return httpx.Response(200, stream=httpx.ByteStream(self.archive))

        client = httpx.Client(transport=httpx.MockTransport(handle))
        with patch("backend.repositories.httpx.Client", return_value=client) as create, patch.dict(
            "os.environ", {"CYBER_GARDEN_REPOSITORIES": ""}
        ):
            self.assertEqual(download_repository("https://github.com/Team/training.git"), self.archive)
        create.assert_called_once_with(timeout=5.0, follow_redirects=False, trust_env=False)

    def test_github_branch_url_downloads_the_selected_branch(self):
        def handle(request):
            self.assertEqual(str(request.url), "https://codeload.github.com/team/project/zip/refs/heads/feature/demo")
            return httpx.Response(200, stream=httpx.ByteStream(self.archive))

        client = httpx.Client(transport=httpx.MockTransport(handle))
        with patch("backend.repositories.httpx.Client", return_value=client):
            self.assertEqual(download_repository("https://github.com/team/project/tree/feature/demo"), self.archive)

    def test_other_hosts_and_invalid_paths_never_open_a_connection(self):
        with patch("backend.repositories.httpx.Client") as create:
            for url, expected in (
                ("https://github.com@127.0.0.1/team/training", "invalid_repository_url"),
                ("https://github.com/team/training/../../other", "invalid_repository_url"),
                ("https://github.com/team/training/tree/main/../other", "invalid_repository_url"),
                ("https://github.com/team/training?token=secret", "invalid_repository_url"),
            ):
                with self.subTest(url=url), self.assertRaises(ApiProblem) as problem:
                    download_repository(url)
                self.assertEqual(problem.exception.code, expected)
            create.assert_not_called()

    def test_redirect_is_refused_and_untrusted_body_is_size_checked(self):
        for response, expected in (
            (httpx.Response(302, headers={"Location": "https://example.invalid/next"}), "repository_download_failed"),
            (httpx.Response(200, stream=httpx.ByteStream(b"x" * 33)), "upload_too_large"),
        ):
            client = httpx.Client(transport=httpx.MockTransport(lambda request: response))
            with patch("backend.repositories.httpx.Client", return_value=client), patch(
                "backend.repositories.MAX_UPLOAD", 32
            ), self.assertRaises(ApiProblem) as problem:
                download_repository("https://github.com/team/training")
            self.assertEqual(problem.exception.code, expected)
