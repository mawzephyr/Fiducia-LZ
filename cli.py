# Fiducia v4.0.7
#!/usr/bin/env python3
"""
CIP-010 Baseline Engine CLI

Command-line interface for managing the baseline engine.
"""
import argparse
import json
import sys
from pathlib import Path


def init_db():
    """Initialize the database."""
    from database import init_db as db_init, SessionLocal
    from database import Group, User
    import bcrypt as bcrypt_lib
    from config import settings
    
    def hash_password(password: str) -> str:
        salt = bcrypt_lib.gensalt()
        return bcrypt_lib.hashpw(password.encode('utf-8'), salt).decode('utf-8')
    
    print("Initializing database...")
    db_init()
    
    db = SessionLocal()
    try:
        # Create default groups
        for group_data in settings.ASSET_GROUPS:
            existing = db.query(Group).filter(Group.id == group_data["id"]).first()
            if not existing:
                group = Group(
                    id=group_data["id"],
                    name=group_data["name"],
                    color=group_data["color"]
                )
                db.add(group)
                print(f"  Created group: {group_data['name']}")
        
        # Create admin user if none exist
        if db.query(User).count() == 0:
            admin = User(
                username="admin",
                password_hash=hash_password("admin123"),
                full_name="Administrator",
                role="admin"
            )
            db.add(admin)
            print("  Created admin user (admin/admin123)")
            
            # Create group users
            for group_data in settings.ASSET_GROUPS:
                user = User(
                    username=group_data["id"],
                    password_hash=hash_password(f"{group_data['id']}123"),
                    full_name=f"{group_data['name']} Baseline Expert",
                    role="baseline_expert",
                    group_id=group_data["id"]
                )
                db.add(user)
                print(f"  Created user: {group_data['id']}")
        
        db.commit()
        print("Database initialized successfully!")
    finally:
        db.close()


def compare_files(before_path: str, after_path: str):
    """Compare two JSON files and print differences."""
    from core import compare_configurations
    
    with open(before_path) as f:
        before = json.load(f)
    
    with open(after_path) as f:
        after = json.load(f)
    
    result = compare_configurations(before, after)
    
    print(f"\nComparing: {before_path} vs {after_path}")
    print("=" * 60)
    
    if result.is_identical:
        print("✅ Files are identical")
    else:
        print(f"⚠️  {result.change_count} difference(s) found:\n")
        
        for change in result.changes:
            print(f"  Field: {change.path}")
            print(f"  Type:  {change.change_type.value}")
            
            if change.change_type.value == "array_modified":
                if change.items_added:
                    print(f"  Added ({len(change.items_added)}):")
                    for item in change.items_added[:3]:
                        print(f"    + {json.dumps(item)}")
                    if len(change.items_added) > 3:
                        print(f"    ... and {len(change.items_added) - 3} more")
                if change.items_removed:
                    print(f"  Removed ({len(change.items_removed)}):")
                    for item in change.items_removed[:3]:
                        print(f"    - {json.dumps(item)}")
                    if len(change.items_removed) > 3:
                        print(f"    ... and {len(change.items_removed) - 3} more")
            else:
                if change.old_value is not None:
                    print(f"  Old: {json.dumps(change.old_value)}")
                if change.new_value is not None:
                    print(f"  New: {json.dumps(change.new_value)}")
            
            print()


def ingest_file(file_path: str, group_id: str = None):
    """Ingest a baseline file into the database."""
    from database import SessionLocal, Asset, BaselineSnapshot
    from core import parse_json_file, compute_config_hash, compare_configurations
    from datetime import datetime
    import json
    
    parsed = parse_json_file(file_path)
    if not parsed:
        print(f"Error: Could not parse {file_path}")
        return
    
    print(f"Ingesting: {parsed.asset_name} from {file_path}")
    
    db = SessionLocal()
    try:
        asset = db.query(Asset).filter(Asset.asset_name == parsed.asset_name).first()
        
        if not asset:
            asset = Asset(
                asset_name=parsed.asset_name,
                group_id=group_id,
                fqdn=parsed.fqdn,
                version=parsed.version
            )
            db.add(asset)
            db.flush()
            
            snapshot = BaselineSnapshot(
                asset_id=asset.id,
                config_json=json.dumps(parsed.config),
                config_hash=compute_config_hash(parsed.config),
                source="cli",
                triggered_by="cli",
                filename=parsed.filename,
                is_current_baseline=True,
                promoted_at=datetime.utcnow(),
                promoted_by="cli"
            )
            db.add(snapshot)
            
            print(f"  ✅ Created new asset: {parsed.asset_name}")
        else:
            current = db.query(BaselineSnapshot).filter(
                BaselineSnapshot.asset_id == asset.id,
                BaselineSnapshot.is_current_baseline == True
            ).first()
            
            if current:
                old_config = json.loads(current.config_json)
                result = compare_configurations(old_config, parsed.config)
                
                if result.is_identical:
                    print(f"  ℹ️  No changes for {parsed.asset_name}")
                else:
                    print(f"  ⚠️  {result.change_count} changes detected for {parsed.asset_name}")
        
        db.commit()
    finally:
        db.close()


def list_assets():
    """List all tracked assets."""
    from database import SessionLocal, Asset
    
    db = SessionLocal()
    try:
        assets = db.query(Asset).all()
        
        if not assets:
            print("No assets tracked.")
            return
        
        print(f"\nTracked Assets ({len(assets)}):")
        print("-" * 60)
        
        for asset in assets:
            print(f"  {asset.asset_name}")
            print(f"    ID:      {asset.id}")
            print(f"    Group:   {asset.group_id or 'Unassigned'}")
            print(f"    State:   {asset.current_state.value}")
            print(f"    FQDN:    {asset.fqdn or 'N/A'}")
            print(f"    Version: {asset.version or 'N/A'}")
            print()
    finally:
        db.close()


def run_server(host: str = "0.0.0.0", port: int = 8000, reload: bool = False, workers: int = 1):
    """Run the FastAPI server."""
    import uvicorn
    uvicorn.run(
        "api.main:app",
        host=host,
        port=port,
        reload=reload,
        workers=workers if not reload else 1  # reload mode requires single worker
    )


def watch_directory(path: str):
    """Watch a directory for new files."""
    from services.watcher import DirectoryWatcher
    from core import ParsedFile
    import time
    
    def on_file(parsed: ParsedFile):
        print(f"📁 Detected: {parsed.filename}")
        print(f"   Asset: {parsed.asset_name}")
        print(f"   FQDN: {parsed.fqdn}")
        print(f"   Version: {parsed.version}")
        print()
    
    print(f"Watching directory: {path}")
    print("Press Ctrl+C to stop\n")
    
    watcher = DirectoryWatcher(path, on_file)
    watcher.start()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping watcher...")
        watcher.stop()


def main():
    parser = argparse.ArgumentParser(
        description="CIP-010 Baseline Engine CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Commands")
    
    # init-db
    subparsers.add_parser("init-db", help="Initialize the database")
    
    # compare
    compare_parser = subparsers.add_parser("compare", help="Compare two JSON files")
    compare_parser.add_argument("before", help="Before/baseline file")
    compare_parser.add_argument("after", help="After/new file")
    
    # ingest
    ingest_parser = subparsers.add_parser("ingest", help="Ingest a baseline file")
    ingest_parser.add_argument("file", help="JSON file to ingest")
    ingest_parser.add_argument("--group", help="Group ID to assign")
    
    # list-assets
    subparsers.add_parser("list-assets", help="List all tracked assets")
    
    # serve
    serve_parser = subparsers.add_parser("serve", help="Run the API server")
    serve_parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")
    serve_parser.add_argument("--port", type=int, default=8000, help="Port to listen on")
    serve_parser.add_argument("--reload", action="store_true", help="Enable auto-reload")
    serve_parser.add_argument("--workers", type=int, default=1, help="Number of worker processes")
    
    # watch
    watch_parser = subparsers.add_parser("watch", help="Watch a directory for files")
    watch_parser.add_argument("path", help="Directory to watch")
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    if args.command == "init-db":
        init_db()
    elif args.command == "compare":
        compare_files(args.before, args.after)
    elif args.command == "ingest":
        ingest_file(args.file, args.group)
    elif args.command == "list-assets":
        list_assets()
    elif args.command == "serve":
        run_server(args.host, args.port, args.reload, args.workers)
    elif args.command == "watch":
        watch_directory(args.path)


if __name__ == "__main__":
    main()
