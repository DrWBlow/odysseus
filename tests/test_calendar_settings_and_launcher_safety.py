"""Behavioral tests for the pure CalDAV form helper."""

import json
import shutil
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]


def _run_node(source: str):
    node = shutil.which("node")
    if not node:
        pytest.skip("node is not installed")
    result = subprocess.run(
        [node, "--input-type=module"],
        input=source,
        text=True,
        capture_output=True,
        cwd=str(ROOT),
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def test_caldav_test_request_helper_preserves_current_basic_edits_and_guards_google():
    source = r'''
      import fs from 'node:fs';
      const code = fs.readFileSync('static/js/caldavAccountForm.js', 'utf8');
      const helper = await import('data:text/javascript,' + encodeURIComponent(code));
      console.log(JSON.stringify({
        basic: helper.buildCalDavTestRequest({
          authType: 'basic', accountId: 'basic-1', url: 'https://current.example/dav',
          username: 'edited-user', password: '',
        }),
        google: helper.buildCalDavTestRequest({ authType: 'oauth2_google', accountId: 'google-1' }),
        unsaved: helper.buildCalDavTestRequest({ authType: 'oauth2_google' }),
        missingId: helper.resolveGoogleAccountId({}, true, ''),
        savedId: helper.resolveGoogleAccountId({ id: 'created-1' }, true, ''),
        newGoogleUrl: helper.defaultCalDavUrl('oauth2_google', undefined, ''),
        switchedGoogleUrl: helper.defaultCalDavUrl('oauth2_google', undefined, ''),
        preservedEmptyUrl: helper.defaultCalDavUrl('oauth2_google', '', 'https://saved.example/dav'),
      }));
    '''
    result = _run_node(source)
    assert result["basic"] == {
        "ok": True,
        "body": {
            "url": "https://current.example/dav",
            "username": "edited-user",
            "password": "",
            "account_id": "basic-1",
        },
    }
    assert result["google"] == {"ok": True, "body": {"account_id": "google-1"}}
    assert result["unsaved"] == {"ok": False, "error": "Save and connect first"}
    assert result["missingId"]["ok"] is False
    assert result["savedId"] == {"ok": True, "accountId": "created-1"}
    assert result["newGoogleUrl"] == "https://apidata.googleusercontent.com/caldav/v2/"
    assert result["switchedGoogleUrl"] == "https://apidata.googleusercontent.com/caldav/v2/"
    assert result["preservedEmptyUrl"] == ""
