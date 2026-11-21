import unittest
from unittest.mock import Mock, patch

from fastapi.testclient import TestClient

from backend.accounts import Account, password_hash, verify_password
from backend.main import create_app


class RegistrationTest(unittest.TestCase):
    password = "synthetic-passphrase"
    registration = {
        "username": "TrainingUser",
        "email": " Training+Library@Example.org ",
        "password": password,
        "confirmPassword": password,
    }

    def setUp(self):
        self.storage = Mock()
        with patch("backend.main.Storage", return_value=self.storage):
            self.client = TestClient(create_app("unused"))
        self.addCleanup(self.client.close)

    def test_registration_stores_normalized_email_and_hashes_the_password(self):
        self.storage.create_account.return_value = True
        response = self.client.post("/accounts/register", json=self.registration)
        self.assertEqual(response.status_code, 201)
        account, digest = self.storage.create_account.call_args.args
        self.assertEqual((account.username, account.email), ("traininguser", "training+library@example.org"))
        self.assertTrue(verify_password(self.password, digest))
        self.assertNotIn(self.password, response.text)

    def test_registration_rejects_missing_email_invalid_email_and_mismatched_passwords(self):
        for payload in (
            {key: value for key, value in self.registration.items() if key != "email"},
            {key: value for key, value in self.registration.items() if key != "confirmPassword"},
            self.registration | {"email": "a..b@example.org"},
            self.registration | {"confirmPassword": "different-passphrase"},
        ):
            self.assertEqual(self.client.post("/accounts/register", json=payload).status_code, 422)
        self.storage.create_account.assert_not_called()
        self.storage.save_session.assert_not_called()

    def test_conflicting_username_or_email_does_not_issue_a_session(self):
        self.storage.create_account.return_value = False
        response = self.client.post("/accounts/register", json=self.registration)
        self.assertEqual((response.status_code, response.json()["code"]), (409, "registration_conflict"))
        self.storage.save_session.assert_not_called()

    def test_existing_account_without_email_can_sign_in_with_username_and_password(self):
        account = Account(id="legacy", username="legacyuser", languagePlugins=[])
        self.storage.account_login.return_value = account, password_hash(self.password)
        response = self.client.post("/accounts/login", json={"username": "LegacyUser", "password": self.password})
        self.assertEqual(response.status_code, 200)
        self.assertIsNone(response.json()["account"]["email"])
        self.storage.account_login.assert_called_once_with("legacyuser")
