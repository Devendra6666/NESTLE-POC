#!/usr/bin/env python3
import requests
import json
import sys
import argparse
import io
from datetime import datetime, timedelta
import base64
import contextlib
import re

# -------------------------------
# Helpers: dual-output "tee"
# -------------------------------
class TeeStdout:
    """Write prints to console and to a buffer simultaneously."""
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
# Core Class
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

    def get_latest_jsm_request(self, jsm_project_key, hours_back=1):
        start_date = (datetime.now() - timedelta(hours=hours_back)).strftime('%Y-%m-%d %H:%M')
        jql = (
            f'project = "{jsm_project_key}" AND summary ~ "create version request" '
            f'AND created >= "{start_date}" ORDER BY created DESC'
        )
        try:
            r = requests.post(
                f"{self.jira_url}/rest/api/3/search",
                headers=self.headers,
                json={"jql": jql, "maxResults": 1, "fields": ["key", "summary", "reporter"]}
            )
            r.raise_for_status()
            data = r.json()
            return data['issues'][0] if data['issues'] else None
        except Exception as e:
            print(f"❌ Error fetching latest JSM request: {e}")
            return None

    def is_valid_version_request(self, summary):
        pattern = r'^\s*create\s+version\s+request\s*-\s*(\d+\.\d+\.\d+)\s*$'
        m = re.match(pattern, summary, flags=re.IGNORECASE)
        if m:
            return True, m.group(1)
        return False, None

    def find_corresponding_jira_issue(self, target_project_key, summary):
        version = summary.split('-')[-1].strip()
        jql = (
            f'project = "{target_project_key}" AND summary ~ "{version}" '
            f'AND status = "BACKLOG" ORDER BY created DESC'
        )
        try:
            r = requests.post(
                f"{self.jira_url}/rest/api/3/search",
                headers=self.headers,
                json={"jql": jql, "maxResults": 5, "fields": ["key", "status", "summary"]}
            )
            r.raise_for_status()
            data = r.json()
            for issue in data.get('issues', []):
                if version and version in issue['fields']['summary']:
                    return issue
            return None
        except Exception as e:
            print(f"❌ Error searching for JIRA issue: {e}")
            return None

    def find_issue_by_exact_summary(self, target_project_key, summary):
        phrase = summary.replace('"', r'\"')
        jql = f'project = "{target_project_key}" AND summary ~ "\\"{phrase}\\"" ORDER BY created DESC'
        try:
            r = requests.post(
                f"{self.jira_url}/rest/api/3/search",
                headers=self.headers,
                json={"jql": jql, "maxResults": 5, "fields": ["key", "status", "summary"]}
            )
            r.raise_for_status()
            data = r.json()
            for issue in data.get('issues', []):
                if issue['fields']['summary'].strip().lower() == summary.strip().lower():
                    return issue
            return None
        except Exception as e:
            print(f"❌ Error searching for exact summary issue: {e}")
            return None

    def delete_issue(self, issue_key):
        try:
            url = f"{self.jira_url}/rest/api/3/issue/{issue_key}"
            r = requests.delete(url, headers=self.headers)
            r.raise_for_status()
            print(f"🗑️ Deleted Jira issue {issue_key}")
            return True
        except Exception as e:
            print(f"❌ Failed to delete issue {issue_key}: {e}")
            return False

    def create_bug(self, project_key, summary, description_adf):
        try:
            url = f"{self.jira_url}/rest/api/3/issue"
            payload = {
                "fields": {
                    "project": {"key": project_key},
                    "summary": summary,
                    "issuetype": {"name": "Bug"},
                    "description": description_adf,
                    "labels": ["invalid-service-request", "auto-created"]
                }
            }
            r = requests.post(url, headers=self.headers, json=payload)
            r.raise_for_status()
            key = r.json().get("key")
            print(f"🐛 Created Bug {key}")
            return key
        except Exception as e:
            print(f"❌ Failed to create Bug: {e}")
            return None

    def link_issues(self, inward_key, outward_key, link_type="Relates"):
        try:
            url = f"{self.jira_url}/rest/api/3/issueLink"
            payload = {
                "type": {"name": link_type},
                "inwardIssue": {"key": inward_key},
                "outwardIssue": {"key": outward_key}
            }
            r = requests.post(url, headers=self.headers, json=payload)
            r.raise_for_status()
            print(f"🔗 Linked {inward_key} ⇄ {outward_key} ({link_type})")
            return True
        except Exception as e:
            print(f"⚠️ Link attempt {inward_key} ⇄ {outward_key} failed/duplicate: {e}")
            return False

    def add_comment_adf(self, issue_key, text):
        try:
            url = f"{self.jira_url}/rest/api/3/issue/{issue_key}/comment"
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
            r = requests.post(url, headers=self.headers, json=payload)
            r.raise_for_status()
            print(f"💬 Comment added to {issue_key}")
            return True
        except Exception as e:
            print(f"❌ Failed to add comment to {issue_key}: {e}")
            return False

    def append_logs_to_description(self, jsm_key, logs):
        try:
            issue_url = f"{self.jira_url}/rest/api/3/issue/{jsm_key}"
            resp = requests.get(issue_url, headers=self.headers, params={"fields": "description"})
            resp.raise_for_status()
            desc_adf = resp.json()["fields"]["description"]
            existing_text = self._adf_to_text(desc_adf) if desc_adf else ""
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            new_adf = {"type": "doc", "version": 1, "content": []}

            if existing_text.strip():
                new_adf["content"].append({
                    "type": "paragraph",
                    "content": [{"type": "text", "text": existing_text}]
                })
                new_adf["content"].append({"type": "rule"})

            new_adf["content"].append({
                "type": "paragraph",
                "content": [{"type": "text", "text": f"---- Console Output ({timestamp}) ----"}]
            })
            new_adf["content"].append({
                "type": "codeBlock",
                "attrs": {"language": "text"},
                "content": [{"type": "text", "text": logs}]
            })

            payload = {"fields": {"description": new_adf}}
            put_resp = requests.put(issue_url, headers=self.headers, json=payload)
            put_resp.raise_for_status()
            print(f"📝 Appended logs to JSM request {jsm_key} description")
        except Exception as e:
            print(f"❌ Failed to append logs to description: {e}")

    def _adf_to_text(self, adf):
        if not adf or "content" not in adf:
            return ""
        out = []
        def walk(node):
            if isinstance(node, dict):
                if node.get("type") == "text":
                    out.append(node.get("text", ""))
                for c in node.get("content", []):
                    walk(c)
            elif isinstance(node, list):
                for c in node:
                    walk(c)
        walk(adf)
        return "\n".join(out).strip()

    def is_user_admin(self, account_id):
        try:
            url = f"{self.jira_url}/rest/api/3/user/groups"
            r = requests.get(url, headers=self.headers, params={"accountId": account_id})
            r.raise_for_status()
            groups = [g['name'].lower() for g in r.json()]
            return any("admin" in g for g in groups)
        except Exception as e:
            print(f"❌ Failed to check admin status: {e}")
            return False

    def get_xray_token(self):
        try:
            resp = requests.post(
                "https://xray.cloud.getxray.app/api/v2/authenticate",
                json={"client_id": self.xray_client_id, "client_secret": self.xray_client_secret}
            )
            resp.raise_for_status()
            return resp.text.strip('"')
        except Exception as e:
            print(f"❌ Failed to authenticate with Xray: {e}")
            return None

    def submit_test_result(self, test_execution_key, test_key, status, comment=""):
        token = self.get_xray_token()
        if not token:
            return None
        url = "https://xray.cloud.getxray.app/api/v2/import/execution"
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }
        payload = {
            "testExecutionKey": test_execution_key,
            "tests": [
                {
                    "testKey": test_key,
                    "status": "PASSED" if status.upper() == "PASS" else "FAILED",
                    "comment": comment
                }
            ]
        }
        try:
            resp = requests.post(url, headers=headers, json=payload)
            resp.raise_for_status()
            print(f"✅ Xray execution updated - {test_key}: {status}")
            return {test_key: status}
        except Exception as e:
            print(f"❌ Error submitting Xray test result for {test_key}: {e}")
            return None

    def link_jsm_with_test_execution(self, jsm_key, test_execution_key):
        return self.link_issues(jsm_key, test_execution_key, link_type="Relates")

# -------------------------------
# Main
# -------------------------------
def main():
    JIRA_URL = "https://deva2cprime.atlassian.net"
    USERNAME = "2019yoga@gmail.com"
    API_TOKEN = "ATATT3xFfGF0pEF0PEtsE4Q7LuIKk8dxd3MUfm82-lnc5ifybRAWcXTAH1AwgdZHyXe8dgQUf-BIj4uqW5BSCXPZWBTv6KRjQ3_1QegVWYuT3izKSAsBEBUE_Ww3CouG2CkiXsrOc2Be3mbsVhsmsCyBqJZuPfpi8yxvPryX6SNAakCvnBKfjko=EA4B5AF8"
    XRAY_CLIENT_ID = "391845606EA543CA964F15D73B576E62"
    XRAY_CLIENT_SECRET = "4d6365ecaf9bee3bfc47e9ca2348ac46bf359bd71167bb846e903f2fae832664"
    JSM_PROJECT_KEY = "NVP"
    TARGET_PROJECT_KEY = "ITNPP"

    parser = argparse.ArgumentParser(description="Validate JSM request -> Jira + Xray and annotate JSM")
    parser.add_argument("--test-execution-key", required=True)
    parser.add_argument("--test-case-key", required=True)
    parser.add_argument("--test-case-2-key")
    parser.add_argument("--test-case-3-key", required=True)  # Release date validation (e.g. ITNPP-51)
    parser.add_argument("--test-case-4-key")
    parser.add_argument("--hours-back", type=int, default=1)
    args = parser.parse_args()

    validator = JSMToJIRAValidator(JIRA_URL, USERNAME, API_TOKEN, XRAY_CLIENT_ID, XRAY_CLIENT_SECRET)
    log_buffer = io.StringIO()
    tee = TeeStdout(sys.__stdout__, log_buffer)

    with contextlib.redirect_stdout(tee):
        print("=" * 60)
        print("🔍 Checking for LATEST JSM service request...")
        latest_jsm = validator.get_latest_jsm_request(JSM_PROJECT_KEY, args.hours_back)
        if not latest_jsm:
            print("❌ No recent JSM requests found")
            return

        jsm_key = latest_jsm["key"]
        jsm_summary = latest_jsm["fields"]["summary"]
        reporter_account_id = latest_jsm["fields"]["reporter"]["accountId"]
        print(f"📋 Found JSM request: {jsm_key} - '{jsm_summary}' by {latest_jsm['fields']['reporter']['displayName']}")

        is_valid, version = validator.is_valid_version_request(jsm_summary)
        if is_valid:
            print(f"✅ Valid version request detected: {version}")
        else:
            print("❌ Invalid request: no version provided after hyphen")

        print("\n🔎 Validating JIRA backlog issue...")
        test1_status = "FAIL"
        test1_message = "No matching backlog issue found"
        if is_valid:
            jira_issue = validator.find_corresponding_jira_issue(TARGET_PROJECT_KEY, jsm_summary)
            if jira_issue:
                test1_status = "PASS"
                test1_message = f"Found matching JIRA issue: {jira_issue['key']}"
                print(f"✅ {test1_message}")
            else:
                print(f"❌ {test1_message}")
        else:
            test1_status = "FAIL"
            test1_message = "Invalid JSM request (missing version); backlog check failed"
            print(f"❌ {test1_message}")

        test2_status = None
        test2_message = None
        if args.test_case_2_key:
            if not is_valid:
                print("\n🧹 Handling invalid request flow...")
                wrong_issue = validator.find_issue_by_exact_summary(TARGET_PROJECT_KEY, jsm_summary)
                if wrong_issue:
                    validator.delete_issue(wrong_issue["key"])
                bug_summary = f"Invalid service request (no version): {jsm_key}"
                bug_desc = {
                    "type": "doc",
                    "version": 1,
                    "content": [{
                        "type": "paragraph",
                        "content": [{"type": "text", "text": f"Customer raised '{jsm_summary}' without a version."}]
                    }]
                }
                bug_key = validator.create_bug(TARGET_PROJECT_KEY, bug_summary, bug_desc)
                if bug_key:
                    validator.link_issues(bug_key, jsm_key, link_type="Relates")
                validator.add_comment_adf(jsm_key, "Invalid request format.")
                test2_status = "FAIL"
                test2_message = "Missing version"
            else:
                test2_status = "PASS"
                test2_message = f"Valid version: {version}"

        # ---------------------------
        # Test Case 3: Release date >= 1 week?
        # ---------------------------
        test3_status = None
        test3_message = None
        if args.test_case_3_key and is_valid:
            try:
                data_resp = requests.get(
                    f"{validator.jira_url}/rest/api/3/issue/{jsm_key}",
                    headers=validator.headers,
                    params={"expand": "names"}
                )
                data_resp.raise_for_status()
                issue_data = data_resp.json()
                fields = issue_data["fields"]
                names = issue_data.get("names", {})

                # find "Release Date" field id dynamically
                release_field = None
                for fid, label in names.items():
                    if label.lower() == "release date":
                        release_field = fid
                        break

                release_date_str = fields.get(release_field) if release_field else None
                today = datetime.today().date()

                if not release_date_str:
                    test3_status = "PASS"
                    test3_message = "No release date provided"
                else:
                    # Parse ISO or human format
                    if isinstance(release_date_str, str) and 'T' in release_date_str:
                        release_date = datetime.fromisoformat(release_date_str.split('+')[0]).date()
                    else:
                        try:
                            release_date = datetime.strptime(release_date_str, "%b %d, %Y, %I:%M %p").date()
                        except Exception:
                            release_date = datetime.strptime(release_date_str, "%Y-%m-%d").date()

                    if (release_date - today).days < 7:
                        test3_status = "FAIL"
                        test3_message = "Release version request is too early (less than 1 week)"
                        bug_summary = f"User requested version too early: {version} (release {release_date_str})"
                        bug_desc = {
                            "type": "doc",
                            "version": 1,
                            "content": [{
                                "type": "paragraph",
                                "content": [{"type": "text", "text": "User requested version too early."}]
                            }]
                        }
                        # bug_key = validator.create_bug(TARGET_PROJECT_KEY, bug_summary, bug_desc)
                        # if bug_key:
                        #     validator.link_issues(bug_key, jsm_key, link_type="Relates")
                        validator.add_comment_adf(jsm_key, "User requested version too early.")
                    else:
                        test3_status = "PASS"
                        test3_message = "Release version request is valid (>= 1 week)"

            except Exception as e:
                print(f"❌ Error checking release date: {e}")
                test3_status = "FAIL"
                test3_message = "Error checking release date"

        # ---------------------------
        # Test Case 4: Admin check
        # ---------------------------
        test4_status = None
        test4_message = None
        if args.test_case_4_key:
            print("\n👤 Checking if reporter is admin...")
            if validator.is_user_admin(reporter_account_id):
                test4_status = "PASS"
                test4_message = "Reporter is an admin user"
                print(f"✅ {test4_message}")
            else:
                test4_status = "FAIL"
                test4_message = "Reporter is NOT an admin user"
                print(f"❌ {test4_message}")

        print("\n🔗 Linking JSM to Test Execution...")
        validator.link_jsm_with_test_execution(jsm_key, args.test_execution_key)

        print("\n🔄 Updating X-ray test execution...")
        execution_statuses = {}
        res1 = validator.submit_test_result(args.test_execution_key, args.test_case_key, test1_status, test1_message)
        if res1: execution_statuses.update(res1)
        if args.test_case_2_key:
            res2 = validator.submit_test_result(args.test_execution_key, args.test_case_2_key, test2_status, test2_message)
            if res2: execution_statuses.update(res2)
        res3 = validator.submit_test_result(args.test_execution_key, args.test_case_3_key, test3_status, test3_message)
        if res3: execution_statuses.update(res3)
        if args.test_case_4_key:
            res4 = validator.submit_test_result(args.test_execution_key, args.test_case_4_key, test4_status, test4_message)
            if res4: execution_statuses.update(res4)

        print("\n" + "=" * 60)
        print(f"🏁 Validation complete for {jsm_key}")
        print("=" * 60)

    validator.add_comment_adf(jsm_key, log_buffer.getvalue())
    if execution_statuses:
        lines = ["📊 Test Execution Results:"]
        for k, v in execution_statuses.items():
            lines.append(f"- {k}: {v}")
        validator.add_comment_adf(jsm_key, "\n".join(lines))


if __name__ == "__main__":
    main()
