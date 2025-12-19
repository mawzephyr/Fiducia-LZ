<!-- Fiducia v4.0.5 -->
# Fiducia

**Infrastructure Baseline Management & Compliance Engine**

Created by [Michael Wooten] and Claude(https://github.com/mawzephyr)

Fiducia is a web-based tool for tracking configuration baselines across critical infrastructure assets. Built for CIP-010 compliance workflows, it enables teams to detect changes, review modifications, and maintain auditable records of approved configurations.

## Key Features

- **Baseline Tracking** — Capture and compare JSON configuration snapshots across assets
- **Change Detection** — Automatic field-level diff with approval/rejection workflow
- **Compliance Dashboard** — Track investigation status, deadlines, and team workloads
- **Change Management Integration** — Associate ticket numbers with baseline changes for audit trails
- **Multi-Team Support** — Role-based access with group assignments (Server, Network, Desktop, Telecom)
- **Scheduled Checks** — Automated compliance scans with configurable intervals
- **Email Alerts** — SMTP notifications for approaching deadlines and compliance failures
- **Report Generation** — Downloadable approval summaries and promotion reports

## Tech Stack

- **Backend:** Python, FastAPI, SQLAlchemy
- **Frontend:** Vanilla JavaScript, Tailwind CSS
- **Database:** SQLite (default), PostgreSQL, MySQL, SQL Server supported

## Architecture

```
fiducia/
├── api/                    # FastAPI application
│   ├── main.py            # Application entry point
│   ├── schemas.py         # Pydantic models
│   └── routes/            # API endpoints
├── core/                   # Core business logic
│   ├── comparison.py      # Deep JSON comparison engine
│   └── file_parser.py     # Filename parsing utilities
├── database/              # SQLAlchemy models
│   ├── connection.py      # Database setup
│   └── models.py          # ORM models
├── services/              # Background services
│   ├── baseline.py        # Baseline computation
│   ├── email_service.py   # SMTP notifications
│   ├── scheduler.py       # Compliance scheduler
│   └── watcher.py         # File system watcher
├── static/                # Frontend
│   └── index.html         # Single-page application
├── config.py              # Application configuration
├── cli.py                 # Command-line interface
└── requirements.txt       # Python dependencies
```

## Quick Start

### 1. Clone and Install Dependencies

```bash
git clone https://github.com/mawzephyr/Fiducia-LZ.git
cd Fiducia-LZ
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Create Data Directory and Initialize Database

```bash
mkdir -p data logs watch
python cli.py init-db
```

### 3. Run the Server

```bash
python cli.py serve
```

Access the UI at: http://localhost:8000

## Default Credentials

| Username | Password | Role |
|----------|----------|------|
| admin | admin123 | Admin |
| server | server123 | Server Team |
| desktop | desktop123 | Desktop Team |
| network | network123 | Network Team |
| telecom | telecom123 | Telecom Team |

## CLI Commands

```bash
python cli.py init-db                         # Initialize database
python cli.py serve                           # Run server
python cli.py serve --host 0.0.0.0 --port 80  # Run on custom host/port
python cli.py compare before.json after.json  # Compare two files
python cli.py ingest config.json --group server  # Ingest baseline file
python cli.py list-assets                     # List all assets
python cli.py watch /path/to/configs          # Watch directory for changes
```

## Configuration

Create a `.env` file or set environment variables:

```env
DATABASE_URL=sqlite:///./data/cip010.db
WATCH_DIRECTORY=/path/to/watch
SCHEDULED_CHECK_DAYS=[1,15]
COMPLIANCE_WINDOW_DAYS=35
SECRET_KEY=your-secret-key-change-in-production
```

### Database Options

```env
# SQLite (default)
DATABASE_URL=sqlite:///./data/cip010.db

# PostgreSQL
DATABASE_URL=postgresql://user:password@localhost:5432/fiducia

# MySQL
DATABASE_URL=mysql+pymysql://user:password@localhost:3306/fiducia

# SQL Server
DATABASE_URL=mssql+pyodbc://user:password@localhost/fiducia?driver=ODBC+Driver+17+for+SQL+Server
```

## Workflow

1. **Upload** — Import JSON configuration files via UI or watch folder
2. **Assign** — Assign assets to groups and promote initial baselines
3. **Detect** — System detects changes when new configs are uploaded
4. **Review** — Review pending changes with field-level diffs
5. **Approve/Reject** — Document decisions with ticket numbers
6. **Finalize** — Merge approved changes into the baseline

## Use Case

Designed for organizations managing infrastructure baselines under NERC CIP-010 or similar regulatory frameworks requiring documented change control and periodic configuration verification.

## Changelog

### v4.0.5 (2025-12-18)
- **Fixed:** Multiple changes to same field now properly supersede previous pending changes instead of creating duplicates
- **Fixed:** Broken duplicate-detection logic that never found existing changes (was checking new_snapshot_id which is always unique)
- **Improved:** Change tracking now maintains one pending change per field, updating with latest value while preserving original baseline reference and compliance deadline
- **Removed:** CIP-010 Compliance Check Schedule section from Settings (scheduler uses default schedule of 1st and 15th)

### v4.0.4 (2025-12-18)
- **Fixed:** Consistent UTC timestamps throughout application (was mixing local and UTC time)
- **Fixed:** Unix timestamp parsing now uses UTC instead of local time
- **Added:** Single-session login enforcement - logging in from a new device automatically logs out previous sessions
- **Added:** UserSession model for tracking active sessions
- **Security:** Session tokens embedded in JWT for server-side session validation

### v4.0.3 (2025-12-17)
- Version sync across all root files

## License

**Proprietary** - All Rights Reserved. No use without express written consent from Michael Wooten. See [LICENSE](LICENSE) for details.
