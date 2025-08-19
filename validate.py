#!/usr/bin/env python3
import requests
import json
import sys
import argparse
import io
from datetime import datetime
import base64
import contextlib
import re

# -------------------------------
# Tee stdout
# -------------------------------
class TeeStdout:
    def __init__(self, *streams):
        self.streams = streams

    def write(self, data):
        for s in self.streams:
            s.write(data)
            s.flush()

    def flush(self):
        for s in self.streams:
            s.flush()

# -------------------------------
# JSM/Jira Validator
# -------------------------------
class JSMToJIRAValidator:
    def __init__(self, jira_url, username, api_token, xray_client_id, xray_client_secret):
        self.jira_url = jira_url.rstrip('/')
        self.auth = base64.b64encode(f"{username}:{api_token}".encode()).decode()
        self.headers = {
            'Authorization': f'Basic {self.auth}',
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
        self.xray_client_id = xray_client_id
        self.xray_client_secret = xray_client_secret

    def get_latest_jsm_request(self, jsm_project_key):
        jql = f'project = {jsm_project_key} AND summary ~ "create version" ORDER BY created DESC'
        r = requests.get(f"{self.jira_url}/rest/api/3/search",
                         headers=self.headers,
                         params={"jql": jql, "maxResults": 1, "fields": "key,summary,reporter"})
        r.raise_for_status()
        data = r.json()
        return data['issues'][0] if data['issues'] else None

    def create_bug_issue(self, project_key, summary, description):
        payload = {
            "fields": {
                "project": {"key": project_key},
                "summary": summary,
                "description": description,
                "issuetype": {"name": "Bug"},
                "priority": {"name": "Medium"}
            }
        }
        r = requests.post(f"{self.jira_url}/rest/api/2/issue", headers=self.headers, json=payload)
        r.raise_for_status()
        return r.json()["key"]

    def add_comment_adf(self, issue_key, text):
        payload = {
            "body": {
                "type": "doc",
                "version": 1,
                "content": [{
                    "type": "paragraph",
                    "content": [{"type": "text", "text": text}]
                }]
            }
        }
        requests.post(f"{self.jira_url}/rest/api/3/issue/{issue_key}/comment",
                      headers=self.headers, json=payload).raise_for_status()

    def get_xray_token(self):
        resp = requests.post(
            "https://xray.cloud.getxray.app/api/v2/authenticate",
            json={"client_id": self.xray_client_id, "client_secret": self.xray_client_secret}
        )
        resp.raise_for_status()
        return resp.text.strip('"')

    def submit_test_result(self, exe_key, test_key, status, comment=""):
        token = self.get_xray_token()
        payload = {
            "testExecutionKey": exe_key,
            "tests": [{
                "testKey": test_key,
                "status": "PASSED" if status.upper() == "PASS" else "FAILED",
                "comment": comment
            }]
        }
        r = requests.post(
            "https://xray.cloud.getxray.app/api/v2/import/execution",
            headers={"Authorization": f"Bearer {token}",
                     "Content-Type": "application/json"},
            json=payload
        )
        r.raise_for_status()
        return {test_key: status}

    def link_issues(self, left_key, right_key):
        payload = {
            "type": {"name": "Relates"},
            "inwardIssue": {"key": left_key},
            "outwardIssue": {"key": right_key}
        }
        requests.post(f"{self.jira_url}/rest/api/3/issueLink",
                      headers=self.headers, json=payload).raise_for_status()

# -------------------------------
# main
# -------------------------------
def main():
    JIRA_URL = "https://deva2cprime.atlassian.net"
    USERNAME = "2019yoga@gmail.com"
    API_TOKEN = "ATATT3xFfGF0eXg6yKrJCGiCgYQUtHcN-APf99q1Eoj6zutyZKEQFSc6ibVFy2DS7gsHcARtFX6YgCxOhSWjfnnmvgpP6zSBH7IZpRYbtxb2WeqPoit2eQoHPb6iixXZg7gWogU90iG1LO0YxYjrdr1WXHYr6oKnKRWR0jRL0vnAO74SpjNFBCY=028D9999"
    XRAY_CLIENT_ID = "391845606EA543CA964F15D73B576E62"
    XRAY_CLIENT_SECRET = "4d6365ecaf9bee3bfc47e9ca2348ac46bf359bd71167bb846e903f2fae832664"

    JSM_PROJECT_KEY = "NVP"
    TARGET_PROJECT_KEY = "ITNPP"

    parser = argparse.ArgumentParser()
    parser.add_argument("--test-execution-key", required=True)
    parser.add_argument("--test-case-3-key", required=True)
    parser.add_argument("--test-case-4-key", required=True)
    parser.add_argument("--test-case-5-key", required=True)
    args = parser.parse_args()

    validator = JSMToJIRAValidator(JIRA_URL, USERNAME, API_TOKEN, XRAY_CLIENT_ID, XRAY_CLIENT_SECRET)
    log_buffer = io.StringIO()
    tee = TeeStdout(sys.__stdout__, log_buffer)

    with contextlib.redirect_stdout(tee):
        print("=" * 60)
        print("🔍 Checking for LATEST JSM service request...")

        latest = validator.get_latest_jsm_request(JSM_PROJECT_KEY)
        if not latest:
            print("❌ No recent JSM requests found")
            return

        jsm_key = latest["key"]
        jsm_summary = latest["fields"]["summary"]
        reporter_name = latest["fields"]["reporter"]["displayName"]
        print(f"📋 Found JSM request: {jsm_key} — '{jsm_summary}'")
        print(f"👤 Reporter: {reporter_name}")

        # Extract version
        version_match = re.search(r'(\d+\.\d+\.\d+)', jsm_summary)
        version = version_match.group(1) if version_match else None

        # ---- Test Case 3 (release date validation) ----
        test3_status = "FAIL"
        test3_message = "No version number found in summary"
        names, fields = {}, {}

        if version:
            print(f"📦 Version detected: {version}")

            resp = requests.get(f"{JIRA_URL}/rest/api/3/issue/{jsm_key}",
                                headers=validator.headers, params={"expand": "names"})
            resp.raise_for_status()
            payload = resp.json()
            fields, names = payload["fields"], payload.get("names", {})

            release_field = None
            for fid, label in names.items():
                if label.lower() == "release date":
                    release_field = fid
                    break

            release_date_str = fields.get(release_field)
            today = datetime.today().date()

            if not release_date_str:
                test3_status, test3_message = "PASS", "No release date provided - validation passed"
                print("✅ No release date provided")
            else:
                print(f"📅 Release date found: {release_date_str}")
                rd = datetime.strptime(release_date_str.split('T')[0], "%Y-%m-%d").date()
                days_until_release = (rd - today).days
                if days_until_release < 7:
                    test3_message = f"Release date is too early ({days_until_release} days away)"
                    validator.add_comment_adf(jsm_key, "❌ Release version request is too early (< 7 days).")
                    print(f"❌ {test3_message}")
                else:
                    test3_status, test3_message = "PASS", f"Release date is valid ({days_until_release} days away)"
                    print(f"✅ {test3_message}")

        # ---- Test Case 4 (reporter check) ----
        if reporter_name == "V.Devendra Reddy":
            test4_status, test4_message = "PASS", "Reporter is allowed (you)"
            print("✅ Request was raised by you")
        else:
            test4_status, test4_message = "FAIL", "Request was raised by someone else"
            print("❌ Request was NOT raised by you")

        # ---- Test Case 5 (env + version logic) ----
        test5_status, test5_message = "FAIL", "❌ Validation not performed"
        test_env = None

        for fid, label in names.items():
            if label.lower() == "test-env":
                test_env = fields.get(fid)
                break

        # ✅ normalize TEST-ENV (dict or string)
        if isinstance(test_env, dict) and "value" in test_env:
            test_env = test_env["value"]
        elif isinstance(test_env, list) and test_env and isinstance(test_env[0], dict):
            test_env = test_env[0].get("value")

        if version and test_env:
            try:
                parts = [int(p) for p in version.split(".")]
                major = parts[0]

                if test_env == "UAT":
                    if major < 10:
                        test5_status, test5_message = "PASS", f"✅ UAT allowed for version {version}"
                    else:
                        test5_message = f"❌ UAT not allowed for version {version} (must be < 10)"

                elif test_env == "PROD":
                    if major > 10 or (major == 10 and len(parts) > 1 and parts[1] > 0):
                        test5_status, test5_message = "PASS", f"✅ PROD allowed for version {version}"
                    else:
                        test5_message = f"❌ PROD requires version > 10, got {version}"

                elif test_env == "SIT":
                    test5_status, test5_message = "PASS", f"✅ SIT accepts any version ({version})"

                else:
                    test5_message = f"❌ Unknown TEST-ENV: {test_env}"

            except Exception as e:
                test5_message = f"❌ Version parsing failed: {e}"

        else:
            test5_message = "❌ Missing version or TEST-ENV field"

        print(test5_message)

        # Collect failures
        failed_tests = []
        if test3_status == "FAIL":
            failed_tests.append(f"Release Date Check: {test3_message}")
        if test4_status == "FAIL":
            failed_tests.append(f"Reporter Check: {test4_message}")
        if test5_status == "FAIL":
            failed_tests.append(f"Env+Version Check: {test5_message}")
            validator.add_comment_adf(jsm_key, test5_message)

        bug_key = None
        if failed_tests:
            print("🐛 Creating bug for failed validations...")
            bug_summary = f"Validation failures for JSM request {jsm_key}"
            bug_description = (f"JSM Request: {jsm_key}  \nSummary: {jsm_summary}  \n\nFailed Validations:\n"
                               + "\n".join([f"- {test}" for test in failed_tests]))
            bug_key = validator.create_bug_issue(TARGET_PROJECT_KEY, bug_summary, bug_description)
            print(f"🐛 Created bug: {bug_key}")
            validator.link_issues(jsm_key, bug_key)
            validator.link_issues(bug_key, args.test_execution_key)

        print("🔗 Linking JSM request to Test Execution...")
        validator.link_issues(jsm_key, args.test_execution_key)

        print("🔄 Updating X-ray...")
        results = {}
        results.update(
            validator.submit_test_result(args.test_execution_key, args.test_case_3_key, test3_status, test3_message)
        )
        results.update(
            validator.submit_test_result(args.test_execution_key, args.test_case_4_key, test4_status, test4_message)
        )
        results.update(
            validator.submit_test_result(args.test_execution_key, args.test_case_5_key, test5_status, test5_message)
        )

        print("=" * 60)
        print(f"🏁 Validation complete for {jsm_key}")
        if bug_key:
            print(f"🐛 Bug created: {bug_key}")

    # Add audit log and results as comments
    validator.add_comment_adf(jsm_key, log_buffer.getvalue())
    if results:
        comment = ["📊 Test Execution Results:"]
        for k, v in results.items():
            comment.append(f"- {k}: {v}")
        if bug_key:
            comment.append(f"🐛 Bug created: {bug_key}")
        validator.add_comment_adf(jsm_key, "\n".join(comment))


if __name__ == "__main__":
    main()
