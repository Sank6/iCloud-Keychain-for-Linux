from icp import diag


def test_redact_removes_secrets_and_personal_identifiers():
    payload = {
        "GsIdmsToken": "token-value",
        "DsPrsId": 123456789,
        "primaryEmail": "person@example.com",
        "fn": "First",
        "ln": "Last",
        "additionalInfo": {
            "phoneNumbers": [{"phoneNumber": "+44 1234 567890"}],
        },
        "status-code": 200,
    }

    redacted = diag.redact(payload)
    rendered = repr(redacted)

    for private_value in (
        "token-value",
        "123456789",
        "person@example.com",
        "First",
        "Last",
        "+44 1234 567890",
    ):
        assert private_value not in rendered
    assert redacted["status-code"] == 200
