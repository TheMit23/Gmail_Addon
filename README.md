# Gmail_Addon
#Security:
Permissions(minimal):
1) "https://www.googleapis.com/auth/gmail.addons.execute"- allow to work in gmail env.
2) "https://www.googleapis.com/auth/gmail.addons.current.message.readonly"- let the addon read the mail.

# SetUp and Installation
This project consists of two main components: the Gmail Add-on (frontend) and the Python Backend service.
### Backend Setup (Local Development)
#### Prerequisites
* Python 3.9+
* [ngrok](https://ngrok.com/) (for exposing the local server to the Google Apps Script environment)
#### Installation Steps

1. Clone the repository and navigate to the backend directory:
   ```bash
   git clone <https://github.com/TheMit23/Gmail_Addon.git>
   cd <https://github.com/TheMit23/Gmail_Addon.git>/backend

2. Create a virtual environment:
    python3 -m venv .venv

3. Activate the virtual environment:
    source .venv/bin/activate

4. Install the required dependencies:
    pip install -r requirements.txt