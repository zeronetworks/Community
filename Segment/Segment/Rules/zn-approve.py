#!/usr/bin/env python3
"""
Zero Networks rule approval helper.
Run with --help for full usage.
"""

import argparse
import base64
import json
import os
import time
from datetime import datetime, timezone
import requests


class ZeroNetworksApproveAPI:
    def __init__(self, api_key=None, debug=False):
        self.api_key_override = api_key
        self.debug = debug
        self.config = self.get_api_config()

    def get_api_config(self):
        api_key = self.api_key_override or os.getenv("ZN_API_KEY")
        if not api_key:
            print("Error: ZN_API_KEY environment variable not set")
            print("Set ZN_API_KEY or pass --api-key")
            raise SystemExit(1)

        base_url = "https://portal.zeronetworks.com/api/v1"
        try:
            parts = api_key.split(".")
            if len(parts) == 3:
                payload = parts[1]
                padding = 4 - len(payload) % 4
                if padding != 4:
                    payload += "=" * padding
                decoded = base64.b64decode(payload)
                data = json.loads(decoded)
                if "aud" in data:
                    base_url = f"https://{data['aud']}/api/v1"
        except Exception:
            pass

        return {
            "api_key": api_key,
            "base_url": base_url,
            "headers": {
                "Authorization": api_key,
                "Content-Type": "application/json",
            },
        }

    def decode_jwt_payload(self, token):
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return None
            payload = parts[1]
            padding = 4 - len(payload) % 4
            if padding != 4:
                payload += "=" * padding
            decoded = base64.b64decode(payload)
            return json.loads(decoded)
        except Exception:
            return None

    def print_token_info(self):
        api_key = self.api_key_override or os.getenv("ZN_API_KEY")
        if not api_key:
            print("Error: ZN_API_KEY environment variable not set")
            print("Set ZN_API_KEY or pass --api-key")
            return
        payload = self.decode_jwt_payload(api_key)
        if not payload:
            print("Error: Unable to decode JWT payload")
            return
        source = "override" if self.api_key_override else "environment"
        print(f"Token source: {source}")
        for field in ("aud", "sub", "name", "scope", "iat", "exp", "iss"):
            value = payload.get(field)
            if field in ("iat", "exp") and isinstance(value, (int, float)):
                value = datetime.fromtimestamp(value, timezone.utc).isoformat().replace("+00:00", "Z")
            print(f"{field}: {value}")

    def make_request(self, method, endpoint, **kwargs):
        url = f"{self.config['base_url']}{endpoint}"
        try:
            response = requests.request(
                method,
                url,
                headers=self.config["headers"],
                timeout=30,
                **kwargs,
            )
            if response.status_code == 429:
                print("Rate limited, waiting 5 seconds...")
                time.sleep(5)
                return self.make_request(method, endpoint, **kwargs)
            if self.debug:
                print(f"HTTP {method} {url} -> {response.status_code}")
            return response
        except requests.exceptions.RequestException as e:
            print(f"Network error: {e}")
            return None

    def check_connectivity(self):
        params = {
            "_limit": 1,
            "_offset": 0,
            "with_count": "true",
        }
        response = self.make_request("GET", "/protection/rules/inbound", params=params)
        if not response:
            print("Connectivity check failed: no response")
            return
        print(f"Connectivity check: HTTP {response.status_code}")
        if response.text:
            print(response.text[:500])

    def get_rules(self, limit=100, direction="inbound", suggestion_type=None):
        endpoint = f"/protection/rules/{direction}"
        params = {
            "_limit": limit,
            "_offset": 0,
            "with_count": "true",
            "order": "desc",
            "orderColumns[]": "createdAt",
        }
        if suggestion_type is not None:
            params["_filters"] = json.dumps([{
                "id": "ruleSuggestionType",
                "includeValues": [str(suggestion_type)],
                "excludeValues": []
            }])
            params["_add_builtins"] = "false"
            params["_add_ancestors"] = "true"
            params["_enrich_remote_ips"] = "true"
        response = self.make_request("GET", endpoint, params=params)
        if response is not None and response.status_code == 200:
            data = response.json()
            return data.get("items", [])
        print(f"Failed to get rules: {response.status_code if response else 'No response'}")
        return []

    def get_rule(self, rule_id, direction="inbound"):
        endpoint = f"/protection/rules/{direction}/{rule_id}"
        response = self.make_request("GET", endpoint)
        if response is not None and response.status_code == 200:
            data = response.json()
            return data.get("item")
        if response is not None and self.debug:
            print(f"HTTP {response.status_code} response:")
            print(f"Headers: {dict(response.headers)}")
            content = response.text or ""
            print(f"Body length: {len(content)}")
            if content:
                print(content[:500])
        print(f"Failed to get rule {rule_id}: {response.status_code if response is not None else 'No response'}")
        return None

    def is_rule_pending(self, rule):
        status = str(rule.get("status", "")).lower()
        review_status = str(rule.get("reviewStatus", "")).lower()
        approval_state = str(rule.get("approvalState", "")).lower()
        is_pending = rule.get("isPendingReview", False)
        state = rule.get("state", rule.get("ruleState"))
        try:
            state_value = int(state) if state is not None else None
        except (TypeError, ValueError):
            state_value = None

        return any(
            [
                "pending" in status,
                "pending" in review_status,
                "pending" in approval_state,
                "delayed" in status,
                "approval" in status,
                "review" in status,
                is_pending,
                state_value in (4, 5),
            ]
        )

    def get_remote_entity_name_map(self, rule):
        name_map = {}
        infos = rule.get("remoteEntityInfos") or []
        for info in infos:
            entity_id = info.get("id")
            name = info.get("name")
            if entity_id and name:
                name_map[entity_id] = name
        return name_map

    def get_rule_local_entity_display(self, rule):
        local_infos = rule.get("localEntityInfos") or []
        for info in local_infos:
            name = info.get("name")
            if name:
                return name
        return rule.get("localEntityId") or "N/A"

    def get_protocol_type_label(self, protocol_type):
        mapping = {0: "ANY", 1: "ICMP", 6: "TCP", 17: "UDP"}
        if protocol_type is None:
            return "ANY"
        try:
            return mapping.get(int(protocol_type), str(protocol_type))
        except (TypeError, ValueError):
            return str(protocol_type)

    def get_rule_protocol_port(self, rule):
        ports_list = rule.get("portsList")
        if isinstance(ports_list, list) and ports_list:
            protocol_entries = []
            port_entries = []
            for item in ports_list:
                if not isinstance(item, dict):
                    continue
                protocol_entries.append(self.get_protocol_type_label(item.get("protocolType")))
                ports_value = item.get("ports")
                if isinstance(ports_value, list):
                    ports_value = ",".join(str(p) for p in ports_value)
                port_entries.append(str(ports_value) if ports_value is not None else "ANY")
            protocol_display = ", ".join(protocol_entries) if protocol_entries else "ANY"
            port_display = ", ".join(port_entries) if port_entries else "ANY"
            return protocol_display, port_display

        protocol = rule.get("protocol")
        port = rule.get("port")
        if protocol or port:
            return protocol or "ANY", port or "ANY"

        services = rule.get("servicesList")
        if services:
            return "SERVICE", ", ".join(services)

        return "ANY", "ANY"

    def print_rule(self, rule, index=None):
        if index is not None:
            print("-" * 60)
            print(f"Rule #{index + 1}")
        source_display = self.get_rule_local_entity_display(rule)
        remote_entity_ids = rule.get("remoteEntityIdsList") or []
        name_map = self.get_remote_entity_name_map(rule)
        remote_names = []
        for remote_id in remote_entity_ids[:5]:
            remote_names.append(name_map.get(remote_id, remote_id))
        destination_display = ", ".join(remote_names) if remote_names else "N/A"
        if len(remote_entity_ids) > 5:
            destination_display += f" (+{len(remote_entity_ids) - 5} more)"

        protocol, port = self.get_rule_protocol_port(rule)
        print(f"Source: {source_display}")
        print(f"Destination: {destination_display}")
        print(f"Protocol: {protocol}")
        print(f"Port: {port}")

    def build_approve_endpoint(self, rule_id, direction="inbound", local_entity_id=None):
        if local_entity_id:
            return f"/assets/{local_entity_id}/protection/rules/{direction}/review/approve/{rule_id}"
        return f"/protection/rules/{direction}/review/approve/{rule_id}"

    def approve_rule(self, rule_id, direction="inbound", local_entity_id=None):
        endpoint = self.build_approve_endpoint(rule_id, direction, local_entity_id)
        response = self.make_request("PUT", endpoint)
        if response is not None and response.status_code == 200:
            print(f"Approved rule {rule_id}")
            return True
        if local_entity_id:
            fallback_endpoint = self.build_approve_endpoint(rule_id, direction)
            fallback_response = self.make_request("PUT", fallback_endpoint)
            if fallback_response is not None and fallback_response.status_code == 200:
                print(f"Approved rule {rule_id}")
                return True
            response = fallback_response
        if response is not None and self.debug:
            print(f"HTTP {response.status_code} response:")
            print(f"Headers: {dict(response.headers)}")
            content = response.text or ""
            print(f"Body length: {len(content)}")
            if content:
                print(content[:500])
        status = response.status_code if response is not None else "No response"
        print(f"Failed to approve rule {rule_id}: {status}")
        return False

    def approve_rules_bulk(self, rule_ids, direction="inbound"):
        success = 0
        total = len(rule_ids)
        print(f"Approving {total} rules...")
        for i, rule_id in enumerate(rule_ids, 1):
            print(f"[{i}/{total}] ", end="")
            rule = self.get_rule(rule_id, direction)
            local_entity_id = rule.get("localEntityId") if rule else None
            if self.approve_rule(rule_id, direction, local_entity_id):
                success += 1
            if i < total:
                time.sleep(0.3)
        print(f"Summary: {success}/{total} rules approved successfully")


def parse_index_ranges(input_text, max_index):
    selected = set()
    if not input_text:
        return selected
    parts = [p.strip() for p in input_text.split(",") if p.strip()]
    for part in parts:
        if "-" in part:
            start_str, end_str = part.split("-", 1)
            try:
                start = int(start_str)
                end = int(end_str)
            except ValueError:
                continue
            if start > end:
                start, end = end, start
            for idx in range(start, end + 1):
                if 1 <= idx <= max_index:
                    selected.add(idx)
        else:
            try:
                idx = int(part)
            except ValueError:
                continue
            if 1 <= idx <= max_index:
                selected.add(idx)
    return selected


def write_selected_ids(output_path, rules, selected_indices):
    ids = []
    for idx in sorted(selected_indices):
        rule = rules[idx - 1]
        rule_id = rule.get("id")
        if rule_id:
            ids.append(rule_id)
    with open(output_path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(ids) + ("\n" if ids else ""))
    print(f"Saved {len(ids)} rule IDs to {output_path}")


def select_rules_interactive(api, rules, output_path, page_size):
    total = len(rules)
    if total == 0:
        print("No pending rules found")
        return

    selected_indices = set()
    page = 0
    total_pages = (total + page_size - 1) // page_size

    def show_page():
        start = page * page_size
        end = min(start + page_size, total)
        print("=" * 60)
        print(f"Page {page + 1}/{total_pages} (rules {start + 1}-{end} of {total})")
        for idx in range(start, end):
            rule = rules[idx]
            display_index = idx + 1
            marker = "*" if display_index in selected_indices else " "
            print("-" * 60)
            rule_id = rule.get("id", "unknown")
            print(f"[{marker}] Rule #{display_index} ({rule_id})")
            api.print_rule(rule)
        print("=" * 60)
        print("Commands: n(ext), p(rev), s(elect) <ranges>, u(nselect) <ranges>, a(ll page), c(lear),")
        print("          save, quit")

    while True:
        show_page()
        command = input("> ").strip()
        if not command:
            continue
        if command in ("n", "next"):
            if page + 1 < total_pages:
                page += 1
            else:
                print("Already at last page")
        elif command in ("p", "prev"):
            if page > 0:
                page -= 1
            else:
                print("Already at first page")
        elif command.startswith("s "):
            ranges = command[2:].strip()
            selected = parse_index_ranges(ranges, total)
            selected_indices.update(selected)
            print(f"Selected {len(selected)} rules")
        elif command.startswith("u "):
            ranges = command[2:].strip()
            unselected = parse_index_ranges(ranges, total)
            selected_indices.difference_update(unselected)
            print(f"Unselected {len(unselected)} rules")
        elif command in ("a", "all"):
            start = page * page_size + 1
            end = min((page + 1) * page_size, total)
            selected_indices.update(range(start, end + 1))
            print(f"Selected page rules {start}-{end}")
        elif command in ("c", "clear"):
            selected_indices.clear()
            print("Cleared selections")
        elif command == "save":
            write_selected_ids(output_path, rules, selected_indices)
        elif command == "quit":
            print("Exiting without saving")
            return
        else:
            print("Unknown command")


def list_command(args):
    api = ZeroNetworksApproveAPI(api_key=args.api_key, debug=args.debug)
    # TODO: Consider adding optional suggestionType filtering for delete approvals later.
    rules = api.get_rules(suggestion_type=1)
    if not rules:
        print("No rules found for suggestionType=1")
        return
    if args.select:
        output_path = args.output or f"zn-approved-rules-{datetime.now().strftime('%Y-%m-%d')}.txt"
        select_rules_interactive(api, rules, output_path, args.page_size)
        return
    for i, rule in enumerate(rules):
        api.print_rule(rule, i)
    print(f"Summary: {len(rules)} inbound rules with suggestionType=1")


def approve_all_command(args):
    api = ZeroNetworksApproveAPI(api_key=args.api_key, debug=args.debug)
    rules = api.get_rules()
    pending_rules = [rule for rule in rules if api.is_rule_pending(rule)]
    if not pending_rules:
        print("No pending rules found")
        return
    rule_ids = [rule.get("id") for rule in pending_rules if rule.get("id")]
    if args.dry_run:
        print(f"DRY RUN: Approve {len(rule_ids)} rules (no changes made)")
        for i, rule_id in enumerate(rule_ids, 1):
            endpoint = api.build_approve_endpoint(rule_id)
            print(f"[{i}/{len(rule_ids)}] PUT {endpoint}")
        return
    confirm = input(f"Approve ALL {len(rule_ids)} pending rules? (yes/no): ")
    if confirm.lower() == "yes":
        api.approve_rules_bulk(rule_ids)
    else:
        print("Approval cancelled")


def apply_command(args):
    api = ZeroNetworksApproveAPI(api_key=args.api_key, debug=args.debug)
    rule_ids = []
    if args.ids:
        rule_ids.extend([item.strip() for item in args.ids.split(",") if item.strip()])
    if args.ids_file:
        with open(args.ids_file, "r", encoding="utf-8") as handle:
            for line in handle:
                value = line.strip()
                if value:
                    rule_ids.append(value)
    rule_ids = list(dict.fromkeys(rule_ids))
    if not rule_ids:
        print("No rule IDs provided")
        return
    if args.dry_run:
        print(f"DRY RUN: Approve {len(rule_ids)} selected rules (no changes made)")
        for i, rule_id in enumerate(rule_ids, 1):
            endpoint = api.build_approve_endpoint(rule_id)
            print(f"[{i}/{len(rule_ids)}] PUT {endpoint}")
        return
    confirm = input(f"Approve {len(rule_ids)} selected rules? (yes/no): ")
    if confirm.lower() == "yes":
        api.approve_rules_bulk(rule_ids)
    else:
        print("Approval cancelled")


def build_parser():
    parser = argparse.ArgumentParser(
        description=(
            "Zero Networks rule approval helper\n\n"
            "Commands:\n"
            "  list         List pending rules (global)\n"
            "  approve-all  Approve all pending rules (global)\n"
            "  apply        Approve a specific list of rule IDs\n\n"
            "Parameters:\n"
            "  --api-key       Zero Networks JWT token (overrides ZN_API_KEY)\n"
            "  --token-info    Show decoded JWT details for the active token\n"
            "  --connectivity  Check API connectivity using the active token\n"
            "  --debug         Print HTTP status and response body for failures\n\n"
            "Examples:\n"
            "  zn-approve.py list --select\n"
            "  zn-approve.py apply --ids-file zn-approved-rules-2026-04-09.txt"
        ),
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "--api-key",
        help="Zero Networks JWT token (overrides ZN_API_KEY)"
    )
    parser.add_argument(
        "--token-info",
        action="store_true",
        help="Show decoded JWT details for the active token"
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Print HTTP status and response body for failures"
    )
    parser.add_argument(
        "--connectivity",
        action="store_true",
        help="Check API connectivity using the active token"
    )
    subparsers = parser.add_subparsers(dest="command")

    list_parser = subparsers.add_parser(
        "list",
        help="List pending rules",
        description=(
            "List pending inbound rules. Use --select for interactive selection.\n\n"
            "Examples:\n"
            "  zn-approve.py list\n"
            "  zn-approve.py list --select\n"
            "  zn-approve.py list --select --output selected-rule-ids.txt"
        ),
        formatter_class=argparse.RawTextHelpFormatter,
    )
    list_parser.add_argument(
        "--select",
        action="store_true",
        help="Interactive selection mode (pagination + ranges)"
    )
    list_parser.add_argument(
        "--output",
        help="Output file for selected rule IDs (default: zn-approved-rules-YYYY-MM-DD.txt)"
    )
    list_parser.add_argument(
        "--page-size",
        type=int,
        default=5,
        help="Rules per page in selection mode"
    )
    list_parser.add_argument(
        "--api-key",
        help="Zero Networks JWT token (overrides ZN_API_KEY)"
    )
    list_parser.add_argument(
        "--debug",
        action="store_true",
        help="Print HTTP status and response body for failures"
    )
    list_parser.set_defaults(func=list_command)

    approve_all = subparsers.add_parser(
        "approve-all",
        help="Approve all pending rules",
        description=(
            "Approve all pending inbound rules.\n\n"
            "Examples:\n"
            "  zn-approve.py approve-all\n"
            "  zn-approve.py approve-all --dry-run"
        ),
        formatter_class=argparse.RawTextHelpFormatter,
    )
    approve_all.add_argument(
        "--dry-run",
        action="store_true",
        help="Show API method/endpoint for each approval"
    )
    approve_all.add_argument(
        "--api-key",
        help="Zero Networks JWT token (overrides ZN_API_KEY)"
    )
    approve_all.add_argument(
        "--debug",
        action="store_true",
        help="Print HTTP status and response body for failures"
    )
    approve_all.set_defaults(func=approve_all_command)
    apply_rules = subparsers.add_parser(
        "apply",
        help="Approve specific rule IDs",
        description=(
            "Approve a selected list of rule IDs.\n\n"
            "Examples:\n"
            "  zn-approve.py apply --ids-file selected-rule-ids.txt\n"
            "  zn-approve.py apply --ids \"id1,id2\" --dry-run"
        ),
        formatter_class=argparse.RawTextHelpFormatter,
    )
    apply_rules.add_argument(
        "--ids",
        help="Comma-separated list of rule IDs"
    )
    apply_rules.add_argument(
        "--ids-file",
        help="Path to file with rule IDs (one per line)"
    )
    apply_rules.add_argument(
        "--dry-run",
        action="store_true",
        help="Show API method/endpoint for each approval"
    )
    apply_rules.add_argument(
        "--api-key",
        help="Zero Networks JWT token (overrides ZN_API_KEY)"
    )
    apply_rules.add_argument(
        "--debug",
        action="store_true",
        help="Print HTTP status and response body for failures"
    )
    apply_rules.set_defaults(func=apply_command)

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    if args.token_info and not args.command:
        api = ZeroNetworksApproveAPI(api_key=args.api_key, debug=args.debug)
        api.print_token_info()
        return
    if args.connectivity and not args.command:
        api = ZeroNetworksApproveAPI(api_key=args.api_key, debug=args.debug)
        api.check_connectivity()
        return
    if not args.command:
        parser.error("the following arguments are required: command")
    args.func(args)


if __name__ == "__main__":
    main()
