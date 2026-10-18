from pathlib import Path
import sys

from dotenv import load_dotenv
from werkzeug.middleware.proxy_fix import ProxyFix

# Ensure the repository root is on sys.path
ROOT_DIR = Path(__file__).resolve().parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from app import create_app
from auth_service import AuthService

# Load local secrets for development. Deployment environment variables take
# precedence because load_dotenv does not override existing values.
load_dotenv(ROOT_DIR / ".env")

auth = AuthService.from_env()
auth.init_db()
app = create_app(
    {
        "DEV_MODE": False,
        "ALLOWED_ORIGINS": auth.cfg.allowed_origins,
        "APP_BASE_URL": auth.cfg.app_base_url,
    },
    identity_resolver=auth.resolve_identity,
)
auth.init_app(app)

# Apply ProxyFix for Render's reverse proxy
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)