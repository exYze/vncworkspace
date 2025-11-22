import httpx
import asyncio
import argparse
import sys

# Configuration
AUTHENTIK_URL = "http://authentik-server:9000"
STUDENT_COUNT = 50

async def create_user(client, username, password, name):
    # 1. Create User
    print(f"Creating user {username}...")
    response = await client.post(
        f"{AUTHENTIK_URL}/api/v3/core/users/",
        json={
            "username": username,
            "name": name,
            "is_active": True
        }
    )
    
    if response.status_code == 400 and "already exists" in response.text:
        print(f"User {username} already exists. Skipping creation.")
        # We still want to set the password, so we need the ID.
        # Fetch the user to get the ID.
        response = await client.get(f"{AUTHENTIK_URL}/api/v3/core/users/?username={username}")
        if response.status_code != 200:
            print(f"Failed to fetch existing user {username}: {response.text}")
            return
        user_id = response.json()["results"][0]["pk"]
    elif response.status_code == 201:
        user_id = response.json()["pk"]
        print(f"User {username} created (ID: {user_id}).")
    else:
        print(f"Failed to create user {username}: {response.status_code} {response.text}")
        return

    # 2. Set Password
    print(f"Setting password for {username}...")
    response = await client.post(
        f"{AUTHENTIK_URL}/api/v3/core/users/{user_id}/set_password/",
        json={"password": password}
    )
    
    if response.status_code == 204:
        print(f"Password set for {username}.")
    else:
        print(f"Failed to set password for {username}: {response.status_code} {response.text}")

async def main():
    parser = argparse.ArgumentParser(description="Bulk create student users in Authentik.")
    parser.add_argument("--token", required=True, help="Authentik API Token")
    args = parser.parse_args()

    headers = {
        "Authorization": f"Bearer {args.token}",
        "Content-Type": "application/json"
    }

    async with httpx.AsyncClient(headers=headers) as client:
        # Verify connection
        try:
            resp = await client.get(f"{AUTHENTIK_URL}/api/v3/core/users/")
            if resp.status_code != 200:
                print(f"Error connecting to Authentik: {resp.status_code} {resp.text}")
                sys.exit(1)
            print("Successfully connected to Authentik API.")
        except Exception as e:
            print(f"Connection failed: {e}")
            sys.exit(1)

        # Create Students
        for i in range(1, STUDENT_COUNT + 1):
            username = f"Student{i}"
            password = f"Student{i}"
            name = f"Student {i}"
            await create_user(client, username, password, name)

    print("\nAll done!")

if __name__ == "__main__":
    asyncio.run(main())
