# 🎉 NeoFi Event Management API

A RESTful API for collaborative event management, built with **Flask**, **SQLite**, and **JWT authentication** 🔐. It supports role-based access control, event versioning, conflict detection, and changelog tracking. Developed as part of the **NeoFi Backend Challenge** 🏁.

---

## ✨ Features

* 🔐 **User Authentication**: Register, login, refresh tokens, and logout with JWT-based authentication.
* 📅 **Event Management**: Create, read, update, and delete events with conflict detection for overlapping events at the same location.
* 🤝 **Collaboration**: Share events with users, assigning roles (Owner, Editor, Viewer) for access control.
* 🕰️ **Versioning**: Track event history, view changelogs, rollback to previous versions, and compare versions with diffs.
* 🚫 **Rate Limiting**: Protects endpoints from abuse (e.g., 10 login attempts per minute).
* ⚡ **Caching**: Improves performance for listing events.
* 📘 **Swagger UI**: Interactive API documentation at `/swagger`.
* 🐳 **Containerization**: Docker support for easy deployment.

---

## 🗂️ Project Structure

```
neofi_event_app/
├── .env                   # 🌿 Environment variables (JWT_SECRET_KEY)
├── .dockerignore          # 🐳 Docker ignore file
├── Dockerfile             # 🐳 Docker configuration
├── app.py                 # 🚀 Main Flask application
├── models.py              # 🧱 SQLAlchemy database models
├── schemas.py             # 📐 Pydantic validation schemas
├── openapi.yaml           # 📘 OpenAPI specification for Swagger
├── neofi_events_db.py     # 🛠️ Database initialization script
├── requirements.txt       # 📦 Python dependencies
├── README.md              # 📄 Project documentation
```

---

## 🧰 Prerequisites

* 🐍 Python 3.8+
* 🐳 Docker (for containerization)
* 🧑‍💻 Git and VS Code (for version control)
* 🗃️ SQLite (default database, included)

---

## ⚙️ Setup Instructions

### 1️⃣ Clone the Repository

```bash
git clone <your-repo-url>
cd neofi_event_app
```

### 2️⃣ Create a Virtual Environment

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3️⃣ Install Dependencies

```bash
pip install -r requirements.txt
```

### 4️⃣ Set Up Environment Variables

Create a `.env` file in the project root:

```
JWT_SECRET_KEY=988c1e08ca6c030b0d359ce34e50aee205387deb2aeac7c47556ff04aca01053
```

### 5️⃣ Initialize the Database

```bash
python neofi_events_db.py
```

> Alternatively, running `app.py` creates the database automatically.

### 6️⃣ Run the Application

```bash
python app.py
```

🌐 Access the API at `http://127.0.0.1:5000`
📘 Swagger UI at `http://127.0.0.1:5000/swagger`

---

## 🔗 API Usage

Use **Postman** or **Swagger UI** to interact with the API. Key endpoints:

* 📝 **Register**
  `POST /api/auth/register`

```json
{
  "username": "testuser",
  "email": "test@example.com",
  "password": "password123"
}
```

* 🔐 **Login**
  `POST /api/auth/login`

```json
{
  "username": "testuser",
  "password": "password123"
}
```

* ➕ **Create Event**
  `POST /api/events` (requires Authorization: Bearer `<access_token>`)

```json
{
  "title": "Team Meeting",
  "description": "Weekly sync",
  "start_time": "2025-06-01T10:00:00",
  "end_time": "2025-06-01T11:00:00",
  "location": "Room 101",
  "is_recurring": false
}
```

* 📄 **List Events**: `GET /api/events?page=1&per_page=10`
* 🤝 **Share Event**: `POST /api/events/<id>/share`
* 🧾 **View Changelog**: `GET /api/events/<id>/changelog`
* 🔁 **Rollback Event**: `POST /api/events/<id>/rollback/<version_id>`

📘 See `openapi.yaml` or Swagger UI for full endpoint documentation.

---

## 🐳 Containerization

### 📦 Build Docker Image

```bash
docker build -t neofi-event-app .
```

### 🚀 Run Container

```bash
docker run -d -p 5000:5000 --name neofi-app neofi-event-app
```

### 💾 Persist Database (optional)

```bash
mkdir db
docker run -d -p 5000:5000 --name neofi-app -v $(pwd)/db:/app neofi-event-app
```

📍 Access the API at `http://localhost:5000`

---

## 🧠 Development Notes

* 🔐 **Security**: Uses salted password hashing, JWT expiration, and rate limiting. Use HTTPS in production.
* 🚀 **Scalability**: Indexes optimize queries. For production, consider **PostgreSQL** and **Redis**.

### 🔧 Missing Features:

* 🔔 Real-time notifications (needs WebSockets/Redis)
* 📦 MessagePack serialization (requires `msgpack`)
* 🔁 Recurring event expansion (stored but not processed — use `python-dateutil`'s `rrule`)

---

## 🤝 Contributing

1. 🍴 Fork the repository
2. 🌿 Create a branch: `git checkout -b feature/xyz`
3. 💾 Commit changes: `git commit -m "Add xyz feature"`
4. 🚀 Push to GitHub: `git push origin feature/xyz`
5. 📬 Open a pull request

---
