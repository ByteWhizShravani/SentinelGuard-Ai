import os

from dotenv import load_dotenv
from flask import Flask
from flask_cors import CORS
from flask_jwt_extended import JWTManager

load_dotenv()

from routes import analyze_bp, auth_bp, scan_results_bp, users_bp


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY", "change-this-in-production")
    app.config["JWT_TOKEN_LOCATION"] = ["headers"]

    JWTManager(app)

    # Allow local frontend development to call this API.
    CORS(app, resources={r"/*": {"origins": "*"}})

    app.register_blueprint(analyze_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(scan_results_bp)
    app.register_blueprint(users_bp)

    @app.get("/health")
    def health_check() -> tuple[dict[str, str], int]:
        return {"status": "ok"}, 200

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(host="0.0.0.0", port=5000, debug=True)
