"""Authorization (IDOR) tests: users must never reach another user's files."""
from __future__ import annotations

import os

from securecloud.extensions import db as _db
from securecloud.models import StoredFile, User

from tests.conftest import get_csrf, login, register, upload_bytes


def _second_client(app, username="bob", email="bob@example.com"):
    client = app.test_client()
    register(client, username=username, email=email)
    return client


def test_other_user_cannot_view_file_details(app, client):
    register(client)
    upload = upload_bytes(client, os.urandom(9000), "private-a.bin")
    assert upload.status_code == 201
    file_id = upload.get_json()["file"]["id"]

    bob = _second_client(app)
    response = bob.get(f"/files/{file_id}", follow_redirects=True)
    assert response.status_code in (200, 404)
    body = response.get_data(as_text=True)
    assert "private-a.bin" not in body, "another user's filename must not be disclosed"
    assert "File not found" in body


def test_other_user_cannot_download_file(app, client):
    register(client)
    payload = os.urandom(12000)
    file_id = upload_bytes(client, payload, "secret-a.bin").get_json()["file"]["id"]

    bob = _second_client(app)
    response = bob.get(f"/files/{file_id}/download", follow_redirects=True)
    assert response.status_code in (200, 404)
    assert payload not in response.data
    assert b"secret" not in response.data


def test_other_user_cannot_delete_file(app, client):
    register(client)
    file_id = upload_bytes(client, os.urandom(5000), "owned-a.bin").get_json()["file"]["id"]

    bob = _second_client(app)
    token = get_csrf(bob, "/files/upload")
    response = bob.post(f"/files/{file_id}/delete",
                        data={"csrf_token": token}, follow_redirects=True)
    assert response.status_code in (200, 404)

    with app.app_context():
        file = _db.session.get(StoredFile, file_id)
        assert file.status == "complete", "the owner's file must be untouched"


def test_other_user_cannot_run_integrity_check(app, client):
    register(client)
    file_id = upload_bytes(client, os.urandom(5000), "checks-a.bin").get_json()["file"]["id"]

    bob = _second_client(app)
    response = bob.post(f"/files/{file_id}/verify",
                        data={"csrf_token": get_csrf(bob, "/files/upload")},
                        headers={"X-Requested-With": "XMLHttpRequest"})
    assert response.status_code == 404
    assert "checks-a.bin" not in response.get_data(as_text=True)


def test_api_listing_only_returns_own_files(app, client):
    register(client)
    upload_bytes(client, os.urandom(3000), "mine-a.bin")

    bob = _second_client(app)
    upload_bytes(bob, os.urandom(3000), "bobs-copy.bin")

    for user_client, expected, forbidden in ((client, "mine-a.bin", "bobs-copy.bin"),
                                             (bob, "bobs-copy.bin", "mine-a.bin")):
        response = user_client.get("/files/api/list", headers={"X-Requested-With": "XMLHttpRequest"})
        assert response.status_code == 200
        body = response.get_data(as_text=True)
        assert expected in body
        assert forbidden not in body


def test_nonexistent_file_returns_same_error_as_forbidden_file(app, client):
    """IDs must not be enumerable: both cases look identical to the caller."""
    register(client)
    file_id = upload_bytes(client, os.urandom(4000), "exists.bin").get_json()["file"]["id"]
    bob = _second_client(app)

    forbidden = bob.get(f"/files/{file_id}", follow_redirects=True)
    missing = bob.get("/files/999999", follow_redirects=True)
    assert "File not found" in forbidden.get_data(as_text=True)
    assert "File not found" in missing.get_data(as_text=True)


def test_ownership_helper_raises_for_mismatched_user(app, client):
    from securecloud.services import FileNotFoundForUser
    from securecloud.services.file_service import owned_file_or_404

    register(client)
    file_id = upload_bytes(client, os.urandom(2000), "owned.bin").get_json()["file"]["id"]

    with app.app_context():
        alice = User.query.filter_by(username="alice").one()
        bob = User(username="bob", email="bob@example.com")
        bob.set_password("Correct-Horse-9!")
        _db.session.add(bob)
        _db.session.commit()

        # The owner succeeds...
        assert owned_file_or_404(file_id, alice).id == file_id
        # ...and anybody else gets the same "not found" error.
        for other in (bob, None):
            try:
                owned_file_or_404(file_id, other)
            except FileNotFoundForUser:
                pass
            else:  # pragma: no cover
                raise AssertionError("access control failed")


def test_unauthenticated_user_cannot_reach_file_api(client):
    for path in ("/files/api/list", "/files/api/1/integrity"):
        response = client.get(path, headers={"X-Requested-With": "XMLHttpRequest"})
        assert response.status_code == 401


def test_anonymous_delete_attempt_is_redirected_to_login(app, client):
    register(client)
    file_id = upload_bytes(client, os.urandom(3000), "anon-target.bin").get_json()["file"]["id"]
    anonymous = app.test_client()
    response = anonymous.post(f"/files/{file_id}/delete", data={}, follow_redirects=False)
    assert response.status_code == 302
    assert "/auth/login" in response.headers["Location"]
