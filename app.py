from flask import Flask, request, jsonify, redirect, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, create_refresh_token
from flask_swagger_ui import get_swaggerui_blueprint
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_caching import Cache
from dotenv import load_dotenv
load_dotenv()
from models import db, User, Event, Permission, EventHistory, Role
from schemas import UserCreate, UserOut, Token, EventCreate, EventOut, PermissionCreate, PermissionOut, EventHistoryOut
from datetime import datetime, timedelta
import hashlib
import os
from pydantic import ValidationError
from deepdiff import DeepDiff

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///neofi_events.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY", "Secret key")
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1)
app.config["JWT_REFRESH_TOKEN_EXPIRES"] = timedelta(days=30)
db.init_app(app)
jwt = JWTManager(app)

# Rate limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

# Caching
cache = Cache(app, config={'CACHE_TYPE': 'simple'})

# Swagger UI setup
SWAGGER_URL = "/swagger"
API_URL = "/openapi.yaml"
swaggerui_blueprint = get_swaggerui_blueprint(
    SWAGGER_URL,
    API_URL,
    config={'app_name': "NeoFi Event Management API"}
)
app.register_blueprint(swaggerui_blueprint, url_prefix=SWAGGER_URL)

# Serve openapi.yaml
@app.route("/openapi.yaml", methods=["GET"])
def serve_openapi():
    try:
        return send_file("openapi.yaml")
    except FileNotFoundError:
        return jsonify({"error": "openapi.yaml not found"}), 404

# Root route
@app.route("/", methods=["GET"])
def home():
    return redirect("/swagger")

# Create database tables
with app.app_context():
    try:
        db.create_all()
        print("Database tables created successfully at:", os.path.abspath("neofi_events.db"))
    except Exception as e:
        print(f"Error creating database tables: {str(e)}")
        raise

# Password hashing with salt
def hash_password(password: str) -> str:
    salt = os.urandom(32).hex()
    return hashlib.sha256((password + salt).encode()).hexdigest() + ":" + salt

def verify_password(stored: str, provided: str) -> bool:
    try:
        stored_hash, salt = stored.split(":")
        return hashlib.sha256((provided + salt).encode()).hexdigest() == stored_hash
    except ValueError:
        return False

# Authentication Endpoints
@app.route("/api/auth/register", methods=["POST"])
@limiter.limit("10 per minute")
def register():
    try:
        data = UserCreate(**request.json)
    except ValidationError as e:
        return jsonify({"error": e.errors()}), 422

    existing_user = User.query.filter_by(username=data.username).first()
    if existing_user:
        return jsonify({"error": "Username already registered"}), 400

    user = User(
        username=data.username,
        email=data.email,
        password=hash_password(data.password),
        role=Role.VIEWER
    )
    db.session.add(user)
    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": f"Database error: {str(e)}"}), 500

    access_token = create_access_token(identity=user.username)
    refresh_token = create_refresh_token(identity=user.username)
    return jsonify({
        "user": UserOut.model_validate(user).dict(),
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer"
    }), 200

@app.route("/api/auth/login", methods=["POST"])
@limiter.limit("10 per minute")
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400

    user = User.query.filter_by(username=username).first()
    if not user or not verify_password(user.password, password):
        return jsonify({"error": "Invalid credentials"}), 401

    access_token = create_access_token(identity=user.username)
    refresh_token = create_refresh_token(identity=user.username)
    return jsonify({
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer"
    }), 200

@app.route("/api/auth/refresh", methods=["POST"])
@jwt_required(refresh=True)
def refresh():
    username = get_jwt_identity()
    access_token = create_access_token(identity=username)
    return jsonify({"access_token": access_token, "token_type": "bearer"}), 200

@app.route("/api/auth/logout", methods=["POST"])
@jwt_required()
def logout():
    return jsonify({"message": "Logged out successfully"}), 200

# Event conflict detection
def check_event_conflict(event_data, event_id=None):
    events = Event.query.filter(
        Event.start_time < event_data.end_time,
        Event.end_time > event_data.start_time
    ).all()
    for existing_event in events:
        if event_id and existing_event.id == event_id:
            continue
        if existing_event.location == event_data.location:
            return True
    return False

# Event Endpoints
@app.route("/api/events", methods=["POST"])
@jwt_required()
@limiter.limit("5 per minute")
def create_event():
    try:
        data = EventCreate(**request.json)
    except ValidationError as e:
        return jsonify({"error": e.errors()}), 422

    if check_event_conflict(data):
        return jsonify({"error": "Event conflicts with existing event at the same location"}), 409

    username = get_jwt_identity()
    user = User.query.filter_by(username=username).first()

    event = Event(
        title=data.title,
        description=data.description,
        start_time=data.start_time,
        end_time=data.end_time,
        location=data.location,
        is_recurring=data.is_recurring,
        recurrence_pattern=data.recurrence_pattern,
        owner_id=user.id
    )
    db.session.add(event)
    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": f"Database error: {str(e)}"}), 500

    permission = Permission(event_id=event.id, user_id=user.id, role=Role.OWNER)
    db.session.add(permission)

    history = EventHistory(
        event_id=event.id,
        version=1,
        title=event.title,
        description=event.description,
        start_time=event.start_time,
        end_time=event.end_time,
        location=event.location,
        is_recurring=event.is_recurring,
        recurrence_pattern=event.recurrence_pattern,
        modified_by=user.id,
        modified_at=datetime.utcnow()
    )
    db.session.add(history)
    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": f"Database error: {str(e)}"}), 500

    return jsonify(EventOut.model_validate(event).dict()), 200

@app.route("/api/events", methods=["GET"])
@jwt_required()
@cache.cached(timeout=60)
def list_events():
    username = get_jwt_identity()
    user = User.query.filter_by(username=username).first()

    permissions = Permission.query.filter_by(user_id=user.id).all()
    event_ids = [p.event_id for p in permissions]
    events = Event.query.filter(Event.id.in_(event_ids)).all()

    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 10, type=int)
    start = (page - 1) * per_page
    end = start + per_page
    paginated_events = events[start:end]

    start_date = request.args.get("start_date")
    end_date = request.args.get("end_date")
    if start_date and end_date:
        try:
            start_date = datetime.fromisoformat(start_date)
            end_date = datetime.fromisoformat(end_date)
            events = [e for e in events if start_date <= e.start_time <= end_date]
            paginated_events = events[start:end]
        except ValueError:
            return jsonify({"error": "Invalid date format"}), 400

    return jsonify({
        "events": [EventOut.model_validate(e).dict() for e in paginated_events],
        "total": len(events),
        "page": page,
        "per_page": per_page
    }), 200

@app.route("/api/events/<int:id>", methods=["GET"])
@jwt_required()
def get_event(id):
    username = get_jwt_identity()
    user = User.query.filter_by(username=username).first()

    permission = Permission.query.filter_by(event_id=id, user_id=user.id).first()
    if not permission:
        return jsonify({"error": "Not authorized"}), 403

    event = Event.query.get_or_404(id)
    return jsonify(EventOut.model_validate(event).dict()), 200

@app.route("/api/events/<int:id>", methods=["PUT"])
@jwt_required()
@limiter.limit("5 per minute")
def update_event(id):
    username = get_jwt_identity()
    user = User.query.filter_by(username=username).first()

    permission = Permission.query.filter_by(event_id=id, user_id=user.id).first()
    if not permission or permission.role not in [Role.OWNER, Role.EDITOR]:
        return jsonify({"error": "Not authorized to edit"}), 403

    try:
        data = EventCreate(**request.json)
    except ValidationError as e:
        return jsonify({"error": e.errors()}), 422

    if check_event_conflict(data, event_id=id):
        return jsonify({"error": "Event conflicts with existing event at the same location"}), 409

    event = Event.query.get_or_404(id)
    latest_version = EventHistory.query.filter_by(event_id=id).order_by(EventHistory.version.desc()).first()
    version = latest_version.version + 1 if latest_version else 1

    event.title = data.title
    event.description = data.description
    event.start_time = data.start_time
    event.end_time = data.end_time
    event.location = data.location
    event.is_recurring = data.is_recurring
    event.recurrence_pattern = data.recurrence_pattern

    history = EventHistory(
        event_id=event.id,
        version=version,
        title=event.title,
        description=event.description,
        start_time=event.start_time,
        end_time=event.end_time,
        location=event.location,
        is_recurring=event.is_recurring,
        recurrence_pattern=event.recurrence_pattern,
        modified_by=user.id,
        modified_at=datetime.utcnow()
    )
    db.session.add(history)
    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": f"Database error: {str(e)}"}), 500

    return jsonify(EventOut.model_validate(event).dict()), 200

@app.route("/api/events/<int:id>", methods=["DELETE"])
@jwt_required()
def delete_event(id):
    username = get_jwt_identity()
    user = User.query.filter_by(username=username).first()

    permission = Permission.query.filter_by(event_id=id, user_id=user.id, role=Role.OWNER).first()
    if not permission:
        return jsonify({"error": "Only owner can delete"}), 403

    event = Event.query.get_or_404(id)
    db.session.delete(event)
    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": f"Database error: {str(e)}"}), 500

    return jsonify({"message": "Event deleted successfully"}), 200

@app.route("/api/events/batch", methods=["POST"])
@jwt_required()
@limiter.limit("3 per minute")
def create_batch_events():
    try:
        events_data = [EventCreate(**event) for event in request.json]
    except ValidationError as e:
        return jsonify({"error": e.errors()}), 422

    username = get_jwt_identity()
    user = User.query.filter_by(username=username).first()
    created_events = []

    for data in events_data:
        if check_event_conflict(data):
            continue
        event = Event(
            title=data.title,
            description=data.description,
            start_time=data.start_time,
            end_time=data.end_time,
            location=data.location,
            is_recurring=data.is_recurring,
            recurrence_pattern=data.recurrence_pattern,
            owner_id=user.id
        )
        db.session.add(event)
        db.session.flush()
        permission = Permission(event_id=event.id, user_id=user.id, role=Role.OWNER)
        history = EventHistory(
            event_id=event.id,
            version=1,
            title=event.title,
            description=event.description,
            start_time=event.start_time,
            end_time=event.end_time,
            location=event.location,
            is_recurring=event.is_recurring,
            recurrence_pattern=event.recurrence_pattern,
            modified_by=user.id,
            modified_at=datetime.utcnow()
        )
        db.session.add(permission)
        db.session.add(history)
        created_events.append(event)

    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": f"Database error: {str(e)}"}), 500

    return jsonify([EventOut.model_validate(e).dict() for e in created_events]), 200

# Collaboration Endpoints
@app.route("/api/events/<int:id>/share", methods=["POST"])
@jwt_required()
def share_event(id):
    username = get_jwt_identity()
    user = User.query.filter_by(username=username).first()

    permission = Permission.query.filter_by(event_id=id, user_id=user.id, role=Role.OWNER).first()
    if not permission:
        return jsonify({"error": "Only owner can share"}), 403

    try:
        data = PermissionCreate(**request.json)
    except ValidationError as e:
        return jsonify({"error": e.errors()}), 422

    target_user = User.query.get(data.user_id)
    if not target_user:
        return jsonify({"error": "User not found"}), 404

    existing_permission = Permission.query.filter_by(event_id=id, user_id=data.user_id).first()
    if existing_permission:
        return jsonify({"error": "Permission already exists"}), 400

    permission = Permission(event_id=id, user_id=data.user_id, role=data.role)
    db.session.add(permission)
    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": f"Database error: {str(e)}"}), 500

    return jsonify(PermissionOut.model_validate(permission).dict()), 200

@app.route("/api/events/<int:id>/permissions", methods=["GET"])
@jwt_required()
def list_permissions(id):
    username = get_jwt_identity()
    user = User.query.filter_by(username=username).first()

    permission = Permission.query.filter_by(event_id=id, user_id=user.id).first()
    if not permission:
        return jsonify({"error": "Not authorized"}), 403

    permissions = Permission.query.filter_by(event_id=id).all()
    return jsonify([PermissionOut.model_validate(p).dict() for p in permissions]), 200

@app.route("/api/events/<int:id>/permissions/<int:user_id>", methods=["PUT"])
@jwt_required()
def update_permission(id, user_id):
    username = get_jwt_identity()
    user = User.query.filter_by(username=username).first()

    owner_permission = Permission.query.filter_by(event_id=id, user_id=user.id, role=Role.OWNER).first()
    if not owner_permission:
        return jsonify({"error": "Only owner can update permissions"}), 403

    try:
        data = PermissionCreate(**request.json)
    except ValidationError as e:
        return jsonify({"error": e.errors()}), 422

    permission = Permission.query.filter_by(event_id=id, user_id=user_id).first()
    if not permission:
        return jsonify({"error": "Permission not found"}), 404

    permission.role = data.role
    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": f"Database error: {str(e)}"}), 500

    return jsonify(PermissionOut.model_validate(permission).dict()), 200

@app.route("/api/events/<int:id>/permissions/<int:user_id>", methods=["DELETE"])
@jwt_required()
def delete_permission(id, user_id):
    username = get_jwt_identity()
    user = User.query.filter_by(username=username).first()

    owner_permission = Permission.query.filter_by(event_id=id, user_id=user.id, role=Role.OWNER).first()
    if not owner_permission:
        return jsonify({"error": "Only owner can delete permissions"}), 403

    permission = Permission.query.filter_by(event_id=id, user_id=user_id).first()
    if not permission:
        return jsonify({"error": "Permission not found"}), 404

    db.session.delete(permission)
    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": f"Database error: {str(e)}"}), 500

    return jsonify({"message": "Permission deleted successfully"}), 200

# Version History Endpoints
@app.route("/api/events/<int:id>/history/<int:version_id>", methods=["GET"])
@jwt_required()
def get_event_version(id, version_id):
    username = get_jwt_identity()
    user = User.query.filter_by(username=username).first()

    permission = Permission.query.filter_by(event_id=id, user_id=user.id).first()
    if not permission:
        return jsonify({"error": "Not authorized"}), 403

    history = EventHistory.query.filter_by(event_id=id, version=version_id).first()
    if not history:
        return jsonify({"error": "Version not found"}), 404

    return jsonify(EventHistoryOut.model_validate(history).dict()), 200

@app.route("/api/events/<int:id>/rollback/<int:version_id>", methods=["POST"])
@jwt_required()
def rollback_event(id, version_id):
    username = get_jwt_identity()
    user = User.query.filter_by(username=username).first()

    permission = Permission.query.filter_by(event_id=id, user_id=user.id, role=Role.OWNER).first()
    if not permission:
        return jsonify({"error": "Only owner can rollback"}), 403

    history = EventHistory.query.filter_by(event_id=id, version=version_id).first()
    if not history:
        return jsonify({"error": "Version not found"}), 404

    event = Event.query.get_or_404(id)
    event.title = history.title
    event.description = history.description
    event.start_time = history.start_time
    event.end_time = history.end_time
    event.location = history.location
    event.is_recurring = history.is_recurring
    event.recurrence_pattern = history.recurrence_pattern

    latest_version = EventHistory.query.filter_by(event_id=id).order_by(EventHistory.version.desc()).first()
    new_version = latest_version.version + 1 if latest_version else 1

    new_history = EventHistory(
        event_id=event.id,
        version=new_version,
        title=event.title,
        description=event.description,
        start_time=event.start_time,
        end_time=event.end_time,
        location=event.location,
        is_recurring=event.is_recurring,
        recurrence_pattern=event.recurrence_pattern,
        modified_by=user.id,
        modified_at=datetime.utcnow()
    )
    db.session.add(new_history)
    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": f"Database error: {str(e)}"}), 500

    return jsonify(EventOut.model_validate(event).dict()), 200

@app.route("/api/events/<int:id>/changelog", methods=["GET"])
@jwt_required()
def get_changelog(id):
    username = get_jwt_identity()
    user = User.query.filter_by(username=username).first()

    permission = Permission.query.filter_by(event_id=id, user_id=user.id).first()
    if not permission:
        return jsonify({"error": "Not authorized"}), 403

    history = EventHistory.query.filter_by(event_id=id).order_by(EventHistory.version).all()
    return jsonify([EventHistoryOut.model_validate(h).dict() for h in history]), 200

@app.route("/api/events/<int:id>/diff/<int:version_id1>/<int:version_id2>", methods=["GET"])
@jwt_required()
def get_diff(id, version_id1, version_id2):
    username = get_jwt_identity()
    user = User.query.filter_by(username=username).first()

    permission = Permission.query.filter_by(event_id=id, user_id=user.id).first()
    if not permission:
        return jsonify({"error": "Not authorized"}), 403

    version1 = EventHistory.query.filter_by(event_id=id, version=version_id1).first()
    version2 = EventHistory.query.filter_by(event_id=id, version=version_id2).first()
    if not version1 or not version2:
        return jsonify({"error": "One or both versions not found"}), 404

    v1_dict = EventHistoryOut.model_validate(version1).dict()
    v2_dict = EventHistoryOut.model_validate(version2).dict()
    diff = DeepDiff(v1_dict, v2_dict, ignore_order=True)

    return jsonify({"diff": diff.to_dict()}), 200

if __name__ == "__main__":
    app.run(debug=True)
