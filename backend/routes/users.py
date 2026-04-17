from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required

from db import fetch_users

users_bp = Blueprint("users", __name__)


@users_bp.get("/users")
@jwt_required()
def fetch_users_handler():
    limit = request.args.get("limit", default=100, type=int)
    users = fetch_users(limit=limit)

    return (
        jsonify(
            {
                "count": len(users),
                "items": users,
            }
        ),
        200,
    )
