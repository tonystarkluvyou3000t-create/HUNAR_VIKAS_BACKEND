"""Operator commands. Run on the server by someone with shell access:

    python -m auth_service.cli init-db
    python -m auth_service.cli pending
    python -m auth_service.cli approve  <org-id|owner-email> --reviewer OPS1 --reason "..."
    python -m auth_service.cli reject   <org-id|owner-email> --reviewer OPS1 --reason "..."
    python -m auth_service.cli revoke   <org-id|owner-email> --reviewer OPS1 --reason "..."
    python -m auth_service.cli suspend|reactivate|delete <email> --reviewer OPS1 --reason "..."
    python -m auth_service.cli seed-synthetic          # development/test only

The reviewer id must appear in AUTH_OPERATOR_IDS: that allow-list plus shell
access is the "trusted approval mechanism". Every action is written to audit_log.
"""
from __future__ import annotations

import argparse
import secrets
import sys
from pathlib import Path

from dotenv import load_dotenv

from .config import AuthConfig
from .service import AuthService


def _require_operator(cfg: AuthConfig, reviewer: str) -> None:
    if reviewer not in cfg.operator_ids:
        sys.exit(f"'{reviewer}' is not listed in AUTH_OPERATOR_IDS.")


def main(argv=None) -> int:
    # Make the CLI behave like the WSGI entry point when run from backend/.
    # Existing deployment environment variables are never overwritten.
    load_dotenv(Path(__file__).resolve().parents[1] / ".env")
    parser = argparse.ArgumentParser(prog="auth_service.cli")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("init-db")
    sub.add_parser("pending")
    sub.add_parser("seed-synthetic")
    for name in ("approve", "reject", "revoke"):
        p = sub.add_parser(name)
        p.add_argument("organisation", help="organization_id or the owner's e-mail")
        p.add_argument("--reviewer", required=True)
        p.add_argument("--reason", default="")
    for name in ("suspend", "reactivate", "delete"):
        p = sub.add_parser(name)
        p.add_argument("email")
        p.add_argument("--reviewer", required=True)
        p.add_argument("--reason", default="")
    args = parser.parse_args(argv)

    cfg = AuthConfig.from_env()
    svc = AuthService(cfg)

    if args.command == "init-db":
        svc.init_db()
        print("Auth tables ready.")
    elif args.command == "pending":
        for row in svc.list_pending_orgs():
            print(f"{row['organization_id']}  {row['name']!r}  owner={row['email']}  "
                  f"owner_status={row['account_status']}  requested={row['created_at']:%Y-%m-%d}")
    elif args.command in ("approve", "reject", "revoke"):
        _require_operator(cfg, args.reviewer)
        print(svc.set_org_approval(args.organisation, args.command, args.reviewer, args.reason))
    elif args.command in ("suspend", "reactivate", "delete"):
        _require_operator(cfg, args.reviewer)
        print(svc.set_account_status(args.email, args.command, args.reviewer, args.reason))
    elif args.command == "seed-synthetic":
        if cfg.environment == "production":
            sys.exit("Refusing to create synthetic accounts in production.")
        svc.init_db()
        specs = [
            ("synthetic.individual@example.test", "individual", "", "pending"),
            ("synthetic.pending.employer@example.test", "employer", "Synthetic Test Workshop (pending)", "pending"),
            ("synthetic.approved.employer@example.test", "employer", "Synthetic Test Workshop", "approved"),
        ]
        print("Synthetic accounts (passwords are random and printed once):")
        for email, role, org, status in specs:
            password = secrets.token_urlsafe(14)
            try:
                svc.create_verified_account(email, password, role, org, status)
                print(f"  {email}  role={role}  org_status={status if role == 'employer' else '-'}  password={password}")
            except Exception as exc:  # e.g. already seeded
                print(f"  {email}  skipped ({type(exc).__name__})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
