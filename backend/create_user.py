#!/usr/bin/env python3
import asyncio
import sys
import argparse
from datetime import datetime, timedelta
from sqlalchemy import select
from eth_account import Account
from app.core.database import async_session_factory
from app.models.domain import User
from app.services.security import generate_one_time_pin

async def main():
    parser = argparse.ArgumentParser(description="Create, promote, or inspect users in LexCorp2")
    parser.add_argument("--address", help="Wallet address to create/promote (e.g., 0x...)")
    parser.add_argument("--role", default="ADMIN", choices=["ADMIN", "MANAGER", "AUDITOR", "USER"], help="Role to assign")
    parser.add_argument("--dept", default="Avionics", help="Department (e.g. Avionics, Cyber, Radar)")
    parser.add_argument("--generate-key", action="store_true", help="Generate a new random Ethereum keypair and register it")
    parser.add_argument("--reset-pin", action="store_true", help="Generate a fresh 3-hour One-Time PIN for existing user")

    args = parser.parse_args()

    private_key_str = None
    if args.generate_key:
        acct = Account.create()
        private_key_str = acct.key.hex()
        address = acct.address.lower()
    elif args.address:
        address = args.address.lower()
    else:
        print("Error: Specify --address <0x...> or --generate-key")
        sys.exit(1)

    pin = generate_one_time_pin(12)
    pin_expiry = datetime.utcnow() + timedelta(hours=3)

    async with async_session_factory() as session:
        result = await session.execute(select(User).filter_by(wallet_address=address))
        user = result.scalars().first()
        if user:
            user.role = args.role
            user.department = args.dept
            user.is_active = True
            if args.reset_pin:
                user.one_time_pin = pin
                user.pin_expires_at = pin_expiry
                user.pin_used = False
                user.onboarding_pending = True
                user.is_totp_enabled = False
                user.totp_secret = None
            await session.commit()
            print(f"\n[+] Updated existing user {address}")
            print(f"    Role:        {args.role}")
            print(f"    Department:  {args.dept}")
            print(f"    Active:      True")
            if args.reset_pin:
                print(f"    One-Time PIN (3 hrs): {pin}")
                print(f"    Expires At:           {pin_expiry.isoformat()}Z")
        else:
            new_user = User(
                wallet_address=address,
                role=args.role,
                department=args.dept,
                name=f"LexCorp {args.role.capitalize()}",
                is_active=True,
                onboarding_pending=True,
                one_time_pin=pin,
                pin_expires_at=pin_expiry,
                pin_used=False
            )
            session.add(new_user)
            await session.commit()
            print(f"\n[+] Created new user {address}")
            print(f"    Role:        {args.role}")
            print(f"    Department:  {args.dept}")
            print(f"    Active:      True")
            print(f"    One-Time PIN (3 hrs): {pin}")
            print(f"    Expires At:           {pin_expiry.isoformat()}Z")

    if private_key_str:
        print("\n=======================================================")
        print("=== PROVISIONING CREDENTIALS (SHARE SECURELY) ===")
        print(f"Address:             {address}")
        print(f"Private Key:         {private_key_str}")
        print(f"One-Time Import PIN: {pin} (Valid for 3 hours, Single-Use)")
        print("=======================================================\n")

if __name__ == "__main__":
    asyncio.run(main())
