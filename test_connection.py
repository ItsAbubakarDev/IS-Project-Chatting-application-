"""
Connection and User List Diagnostic Script
Run this to test if the server and authentication are working correctly
"""
import requests
import json

def test_connection():
    """Test connection to the chat server"""
    
    BASE_URL = "http://127.0.0.1:8000"
    
    print("=" * 60)
    print("CHAT SERVER DIAGNOSTIC TEST")
    print("=" * 60)
    print()
    
    # Test 1: Server Health
    print("TEST 1: Server Health Check")
    print("-" * 60)
    try:
        resp = requests.get(f"{BASE_URL}/", timeout=5)
        if resp.status_code == 200:
            print("✅ Server is responding")
            data = resp.json()
            print(f"   Version: {data.get('version')}")
            print(f"   Status: {data.get('status')}")
        else:
            print(f"❌ Server returned status {resp.status_code}")
            return False
    except requests.exceptions.ConnectionError:
        print("❌ Cannot connect to server")
        print("   Make sure the server is running: python backend/main.py")
        return False
    except Exception as e:
        print(f"❌ Error: {e}")
        return False
    
    print()
    
    # Test 2: DH Parameters
    print("TEST 2: DH Parameters Availability")
    print("-" * 60)
    try:
        resp = requests.get(f"{BASE_URL}/dh-parameters")
        if resp.status_code == 200:
            print("✅ DH parameters are available")
            data = resp.json()
            print(f"   Description: {data.get('description')}")
        else:
            print(f"❌ DH parameters request failed: {resp.status_code}")
    except Exception as e:
        print(f"❌ Error: {e}")
    
    print()
    
    # Test 3: Try to login (or create test user)
    print("TEST 3: User Authentication")
    print("-" * 60)
    
    test_users = [
        {"username": "Asma", "email": "asma@gmail.com", "password": "Asma@N00rPass"},
        {"username": "Iqra", "email": "iqra@gmail.com", "password": "Iqr@Hayd3r12"}
    ]
    
    tokens = {}
    
    for user in test_users:
        print(f"\nTesting user: {user['username']}")
        
        # Try to login first
        resp = requests.post(
            f"{BASE_URL}/login",
            data={"username": user['username'], "password": user['password']}
        )
        
        if resp.status_code == 200:
            data = resp.json()
            token = data['access_token']
            tokens[user['username']] = token
            print(f"✅ {user['username']} logged in successfully")
            print(f"   Token (first 20 chars): {token[:20]}...")
            print(f"   Has public key: {bool(data.get('public_key'))}")
        else:
            print(f"⚠️  {user['username']} login failed (user might not exist yet)")
            print(f"   This is expected if users haven't been created")
    
    print()
    
    # Test 4: Get Users List
    if tokens:
        print("TEST 4: User List Retrieval")
        print("-" * 60)
        
        for username, token in tokens.items():
            print(f"\nFetching users as {username}:")
            
            headers = {"Authorization": f"Bearer {token}"}
            resp = requests.get(f"{BASE_URL}/users", headers=headers)
            
            if resp.status_code == 200:
                users = resp.json()
                print(f"✅ Successfully fetched {len(users)} users")
                
                if len(users) == 0:
                    print("   ⚠️  No other users found!")
                    print("   This is normal if only one user is registered")
                else:
                    print("   Users:")
                    for user in users:
                        status = "🟢 Online" if user.get('is_online') else "⚫ Offline"
                        has_key = "🔑 Has key" if user.get('public_key') else "❌ No key"
                        print(f"     - {user['username']}: {status}, {has_key}")
            elif resp.status_code == 401:
                print(f"❌ Authentication failed (401)")
                print("   Token might be invalid or expired")
            else:
                print(f"❌ Failed to fetch users: {resp.status_code}")
                print(f"   Response: {resp.text[:200]}")
    else:
        print("TEST 4: Skipped (no authenticated users)")
    
    print()
    print("=" * 60)
    print("DIAGNOSTIC COMPLETE")
    print("=" * 60)
    print()
    
    # Summary and recommendations
    print("RECOMMENDATIONS:")
    print("-" * 60)
    
    if not tokens:
        print("1. ⚠️  No users could login")
        print("   → Create users by running the client and registering")
        print("   → python client/main.py")
    else:
        print("1. ✅ Authentication is working")
    
    print("\n2. To test the full flow:")
    print("   a) Open terminal 1: python client/main.py")
    print("   b) Register as 'alice'")
    print("   c) Open terminal 2: python client/main.py")
    print("   d) Register as 'bob'")
    print("   e) Check if users appear in each other's list")
    
    print("\n3. If users still don't appear:")
    print("   → Check server logs for errors")
    print("   → Verify the database file exists: backend/chat.db")
    print("   → Try deleting chat.db and restarting server")
    
    return True


if __name__ == "__main__":
    test_connection()