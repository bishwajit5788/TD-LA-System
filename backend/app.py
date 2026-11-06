import os
import sys
from backend.utils.limiter import limiter

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, jsonify
from flask_cors import CORS


def create_app():
    app = Flask(__name__)
    CORS(app, resources={r"/api/*": {"origins": ["http://127.0.0.1:5500"]}})
    limiter.init_app(app)

    from backend.routes.api import api
    app.register_blueprint(api, url_prefix="/api")

    @app.route("/")
    def home():
        return jsonify({
            "message"  : "AI Threat Detection API is running",
            "status"   : "online",
            "endpoints": [
                "GET  /api/logs",
                "GET  /api/alerts",
                "GET  /api/stats",
                "GET  /api/threats/timeline",
                "GET  /api/threats/top-ips",
                "POST /api/analyse"
            ]
        })

    @app.route("/health")
    def health():
        return jsonify({"status": "ok"}), 200

    @app.errorhandler(404)
    def not_found(e):
        return jsonify({"success": False, "error": "Endpoint not found"}), 404

    @app.errorhandler(500)
    def server_error(e):
        return jsonify({"success": False, "error": str(e)}), 500

    return app


if __name__ == "__main__":
    os.makedirs("data", exist_ok=True)
    os.makedirs("backend/models", exist_ok=True)

    if not os.path.exists("data/sample_logs.csv"):
        os.system(f"{sys.executable} data/generate_logs.py")

    if not os.path.exists("backend/models/isolation_forest.pkl"):
        os.system(f"{sys.executable} ml/train_model.py")

    from backend.utils.database import init_database
    init_database()

    from ml.detector import detector
    detector.load_model()

    app = create_app()
    debug_mode = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    app.run(
    host="127.0.0.1",
    port=5001,
    debug=False,
    use_reloader=False
    )