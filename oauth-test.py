
#!/usr/bin/env python3

import requests
from requests_oauthlib import OAuth1Session
import time
import sys
import re
from html.parser import HTMLParser

# Configuration
CONSUMER_KEY = "oauth1_consumer_key"
CONSUMER_SECRET = "oauth1_consumer_secret"
REQUEST_TOKEN_URL = "http://localhost:8000/oauth1/request_token"
AUTHORIZE_URL = "http://localhost:8000/oauth1/authorize"
ACCESS_TOKEN_URL = "http://localhost:8000/oauth1/access_token"
PROTECTED_RESOURCE_URL = "http://localhost:8000/oauth1/api/user"
CALLBACK_URL = "oob"  # Out-of-band for desktop apps

class bcolors:
    """ANSI color codes for terminal output"""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def print_step(step_num, title):
    """Print step header"""
    print(f"\n{bcolors.BOLD}{bcolors.BLUE}{'='*60}{bcolors.ENDC}")
    print(f"{bcolors.BOLD}{bcolors.BLUE}STEP {step_num}: {title}{bcolors.ENDC}")
    print(f"{bcolors.BOLD}{bcolors.BLUE}{'='*60}{bcolors.ENDC}\n")

def print_success(message):
    """Print success message"""
    print(f"{bcolors.GREEN}✅ {message}{bcolors.ENDC}")

def print_error(message):
    """Print error message"""
    print(f"{bcolors.RED}❌ {message}{bcolors.ENDC}")

def print_info(label, value):
    """Print info message"""
    print(f"{bcolors.CYAN}{label}:{bcolors.ENDC} {bcolors.YELLOW}{value}{bcolors.ENDC}")

def extract_verifier_from_html(html_content):
    """
    Extract verifier code from authorization response HTML
    Handles multiple HTML formats
    """
    # Try multiple regex patterns to find the verifier
    patterns = [
        # Pattern 1: Inside h1 tag with style
        r'<h1[^>]*>([A-Za-z0-9_\-]{32,})</h1>',
        # Pattern 2: After "verifier"
        r'verifier["\'>:\s]*([A-Za-z0-9_\-]{32,})',
        # Pattern 3: Just long alphanumeric strings (40+ chars)
        r'([A-Za-z0-9_\-]{40,})',
        # Pattern 4: Between specific text markers
        r'letter-spacing[^>]*>([A-Za-z0-9_\-]{32,})',
    ]
    
    for pattern in patterns:
        match = re.search(pattern, html_content)
        if match:
            verifier = match.group(1)
            # Validate it looks like a token (long enough and alphanumeric)
            if len(verifier) >= 32 and all(c.isalnum() or c in '_-' for c in verifier):
                return verifier
    
    return None

def step1_request_token():
    """
    Step 1: Request Token
    Get temporary credentials from the authorization server
    """
    print_step(1, "Request Token")
    
    try:
        # Create OAuth1 session to request temporary credentials
        oauth = OAuth1Session(
            client_key=CONSUMER_KEY,
            client_secret=CONSUMER_SECRET,
            callback_uri=CALLBACK_URL
        )
        
        print(f"{bcolors.CYAN}Requesting temporary credentials from:{bcolors.ENDC}")
        print(f"  {REQUEST_TOKEN_URL}\n")
        
        # Fetch request token
        response = oauth.fetch_request_token(REQUEST_TOKEN_URL)
        
        request_token = response.get('oauth_token')
        request_token_secret = response.get('oauth_token_secret')
        
        if not request_token or not request_token_secret:
            print_error("Failed to parse request token response")
            return None, None
        
        print_success("Request Token obtained!")
        print_info("oauth_token", request_token)
        print_info("oauth_token_secret", request_token_secret)
        
        return request_token, request_token_secret
        
    except Exception as e:
        print_error(f"Failed to get request token: {str(e)}")
        return None, None

def step2_authorize(request_token):
    """
    Step 2: User Authorization
    User visits authorization URL and grants permission
    """
    print_step(2, "User Authorization")
    
    try:
        # Build authorization URL
        auth_url = f"{AUTHORIZE_URL}?oauth_token={request_token}"
        
        print(f"{bcolors.CYAN}User authorization URL:{bcolors.ENDC}")
        print(f"  {auth_url}\n")
        
        print(f"{bcolors.CYAN}Opening authorization form...{bcolors.ENDC}\n")
        
        # Get the authorization form
        response = requests.get(auth_url)
        
        if response.status_code != 200:
            print_error(f"Failed to get authorization form: {response.status_code}")
            return None
        
        print(f"{bcolors.YELLOW}Submitting authorization (user: user@example.com / password: password123)...{bcolors.ENDC}\n")
        
        # Submit authorization form
        auth_response = requests.post(
            f"{AUTHORIZE_URL}",
            data={
                "oauth_token": request_token,
                "username": "user@example.com",
                "password": "password123",
                "action": "authorize"
            },
            allow_redirects=True
        )
        
        # Check for success
        if "Authorization Successful" in auth_response.text or "✅" in auth_response.text:
            # Extract verifier from HTML
            verifier = extract_verifier_from_html(auth_response.text)
            
            if verifier:
                print_success("Authorization successful!")
                print_info("Verifier", verifier)
                return verifier
            else:
                print_error("Authorization successful but could not extract verifier")
                print(f"\n{bcolors.YELLOW}Response HTML:{bcolors.ENDC}")
                print(auth_response.text[:500])
                
                # Fallback: Ask user to manually extract
                print(f"\n{bcolors.YELLOW}Please manually extract the verifier code from the response above.{bcolors.ENDC}")
                print(f"{bcolors.YELLOW}It's the long alphanumeric string shown on the authorization page.{bcolors.ENDC}")
                verifier = input(f"\n{bcolors.CYAN}Enter verifier manually: {bcolors.ENDC}")
                
                if verifier and len(verifier) >= 20:
                    return verifier
                else:
                    print_error("Invalid verifier provided")
                    return None
        else:
            print_error("Authorization failed")
            print(f"Response: {auth_response.text[:300]}")
            return None
            
    except Exception as e:
        print_error(f"Failed during authorization: {str(e)}")
        return None

def step3_access_token(request_token, request_token_secret, verifier):
    """
    Step 3: Access Token
    Exchange authorized request token for permanent access token
    """
    print_step(3, "Access Token Exchange")
    
    try:
        print(f"{bcolors.CYAN}Exchanging request token for access token...{bcolors.ENDC}\n")
        
        # Create OAuth1 session with request token and verifier
        oauth = OAuth1Session(
            client_key=CONSUMER_KEY,
            client_secret=CONSUMER_SECRET,
            resource_owner_key=request_token,
            resource_owner_secret=request_token_secret,
            verifier=verifier
        )
        
        # Fetch access token
        response = oauth.fetch_access_token(ACCESS_TOKEN_URL)
        
        access_token = response.get('oauth_token')
        access_token_secret = response.get('oauth_token_secret')
        
        if not access_token or not access_token_secret:
            print_error("Failed to parse access token response")
            print(f"Response: {response}")
            return None, None
        
        print_success("Access Token obtained!")
        print_info("oauth_token", access_token)
        print_info("oauth_token_secret", access_token_secret)
        
        return access_token, access_token_secret
        
    except Exception as e:
        print_error(f"Failed to get access token: {str(e)}")
        print(f"Details: {str(e)}")
        return None, None

def step4_access_resource(access_token, access_token_secret):
    """
    Step 4: Access Protected Resource
    Use access token to access protected resource
    """
    print_step(4, "Access Protected Resource")
    
    try:
        print(f"{bcolors.CYAN}Accessing protected resource:{bcolors.ENDC}")
        print(f"  {PROTECTED_RESOURCE_URL}\n")
        
        # Create authenticated request
        oauth = OAuth1Session(
            client_key=CONSUMER_KEY,
            client_secret=CONSUMER_SECRET,
            resource_owner_key=access_token,
            resource_owner_secret=access_token_secret
        )
        
        # Access protected resource
        response = oauth.get(PROTECTED_RESOURCE_URL)
        
        if response.status_code != 200:
            print_error(f"Failed to access resource: {response.status_code}")
            print(f"Response: {response.text}")
            return False
        
        print_success("Protected resource accessed!")
        
        # Parse and display response
        try:
            data = response.json()
            print(f"\n{bcolors.CYAN}Response Data:{bcolors.ENDC}")
            for key, value in data.items():
                print_info(key, value)
        except:
            print(f"Response: {response.text}")
        
        return True
        
    except Exception as e:
        print_error(f"Failed to access protected resource: {str(e)}")
        return False

def run_complete_flow():
    """
    Run the complete OAuth1 flow
    """
    print(f"\n{bcolors.BOLD}{bcolors.HEADER}")
    print("╔" + "="*58 + "╗")
    print("║" + " "*10 + "OAuth1 Complete Flow - Desktop App Demo" + " "*10 + "║")
    print("╚" + "="*58 + "╝")
    print(f"{bcolors.ENDC}\n")
    
    print(f"{bcolors.CYAN}Configuration:{bcolors.ENDC}")
    print_info("Consumer Key", CONSUMER_KEY)
    print_info("Callback", CALLBACK_URL)
    print_info("Request Token URL", REQUEST_TOKEN_URL)
    print_info("Authorize URL", AUTHORIZE_URL)
    print_info("Access Token URL", ACCESS_TOKEN_URL)
    print_info("Protected Resource URL", PROTECTED_RESOURCE_URL)
    
    # Step 1: Request Token
    request_token, request_token_secret = step1_request_token()
    if not request_token:
        return False
    
    time.sleep(1)
    
    # Step 2: Authorization
    verifier = step2_authorize(request_token)
    if not verifier:
        return False
    
    time.sleep(1)
    
    # Step 3: Access Token
    access_token, access_token_secret = step3_access_token(
        request_token, request_token_secret, verifier
    )
    if not access_token:
        return False
    
    time.sleep(1)
    
    # Step 4: Access Protected Resource
    success = step4_access_resource(access_token, access_token_secret)
    
    # Summary
    print(f"\n{bcolors.BOLD}{bcolors.BLUE}{'='*60}{bcolors.ENDC}")
    if success:
        print(f"{bcolors.BOLD}{bcolors.GREEN}✅ OAuth1 Flow Complete!{bcolors.ENDC}")
        print(f"{bcolors.CYAN}All steps executed successfully.{bcolors.ENDC}")
    else:
        print(f"{bcolors.BOLD}{bcolors.RED}❌ OAuth1 Flow Failed!{bcolors.ENDC}")
        print(f"{bcolors.CYAN}One or more steps encountered errors.{bcolors.ENDC}")
    print(f"{bcolors.BOLD}{bcolors.BLUE}{'='*60}{bcolors.ENDC}\n")
    
    return success

if __name__ == "__main__":
    try:
        # Run the complete flow
        success = run_complete_flow()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print(f"\n{bcolors.YELLOW}Flow interrupted by user.{bcolors.ENDC}\n")
        sys.exit(1)
    except Exception as e:
        print(f"\n{bcolors.RED}Unexpected error: {str(e)}{bcolors.ENDC}\n")
        import traceback
        traceback.print_exc()
        sys.exit(1)

