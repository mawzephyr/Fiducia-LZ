"""
File System Watcher Service for CIP-010 Baseline Engine.

Uses watchdog to monitor a directory for new JSON files
and automatically ingest them into the system.
"""
import os
import time
import logging
from pathlib import Path
from typing import Callable, Optional
from datetime import datetime

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileCreatedEvent, FileModifiedEvent

from core.file_parser import parse_json_file, ParsedFile
from config import settings

logger = logging.getLogger(__name__)


class BaselineFileHandler(FileSystemEventHandler):
    """
    Handles file system events for baseline JSON files.
    
    When a new JSON file is detected, it parses and processes it.
    """
    
    def __init__(self, on_file_detected: Callable[[ParsedFile], None]):
        """
        Initialize handler.
        
        Args:
            on_file_detected: Callback function when a valid JSON file is found
        """
        self.on_file_detected = on_file_detected
        self._processed_files = set()  # Track processed files to avoid duplicates
    
    def on_created(self, event: FileCreatedEvent):
        """Handle new file creation."""
        if event.is_directory:
            return
        
        if self._is_json_file(event.src_path):
            # Small delay to ensure file is fully written
            time.sleep(0.5)
            self._process_file(event.src_path)
    
    def on_modified(self, event: FileModifiedEvent):
        """Handle file modification (useful for files that are created then written)."""
        if event.is_directory:
            return
        
        if self._is_json_file(event.src_path):
            self._process_file(event.src_path)
    
    def _is_json_file(self, path: str) -> bool:
        """Check if file is a JSON file."""
        return path.lower().endswith('.json')
    
    def _process_file(self, file_path: str):
        """Parse and process a JSON file."""
        # Get absolute path for consistent tracking
        abs_path = os.path.abspath(file_path)
        
        # Get file modification time to detect actual changes
        try:
            mtime = os.path.getmtime(abs_path)
            file_key = f"{abs_path}:{mtime}"
        except OSError:
            return
        
        # Skip if already processed this version
        if file_key in self._processed_files:
            return
        
        logger.info(f"Processing new file: {file_path}")
        
        # Parse the file
        parsed = parse_json_file(file_path)
        
        if parsed:
            self._processed_files.add(file_key)
            
            # Limit cache size
            if len(self._processed_files) > 1000:
                # Remove oldest entries (simple approach)
                oldest = list(self._processed_files)[:500]
                for key in oldest:
                    self._processed_files.discard(key)
            
            # Call the callback
            try:
                self.on_file_detected(parsed)
            except Exception as e:
                logger.error(f"Error processing file {file_path}: {e}")
        else:
            logger.warning(f"Failed to parse file: {file_path}")


class DirectoryWatcher:
    """
    Watches a directory for new baseline JSON files.
    
    Usage:
        watcher = DirectoryWatcher("/path/to/watch", callback)
        watcher.start()
        # ... later
        watcher.stop()
    """
    
    def __init__(
        self, 
        watch_path: str, 
        on_file_detected: Callable[[ParsedFile], None],
        recursive: bool = True
    ):
        """
        Initialize the directory watcher.
        
        Args:
            watch_path: Directory path to monitor
            on_file_detected: Callback when a file is detected
            recursive: Whether to watch subdirectories
        """
        self.watch_path = Path(watch_path)
        self.recursive = recursive
        self.on_file_detected = on_file_detected
        
        self._observer: Optional[Observer] = None
        self._handler: Optional[BaselineFileHandler] = None
        self._running = False
    
    def start(self):
        """Start watching the directory."""
        if self._running:
            logger.warning("Watcher already running")
            return
        
        if not self.watch_path.exists():
            logger.error(f"Watch path does not exist: {self.watch_path}")
            raise FileNotFoundError(f"Watch path not found: {self.watch_path}")
        
        logger.info(f"Starting directory watcher on: {self.watch_path}")
        
        self._handler = BaselineFileHandler(self.on_file_detected)
        self._observer = Observer()
        self._observer.schedule(
            self._handler, 
            str(self.watch_path), 
            recursive=self.recursive
        )
        self._observer.start()
        self._running = True
        
        logger.info("Directory watcher started")
    
    def stop(self):
        """Stop watching the directory."""
        if not self._running:
            return
        
        logger.info("Stopping directory watcher")
        
        if self._observer:
            self._observer.stop()
            self._observer.join(timeout=5)
            self._observer = None
        
        self._handler = None
        self._running = False
        
        logger.info("Directory watcher stopped")
    
    def is_running(self) -> bool:
        """Check if watcher is running."""
        return self._running
    
    def scan_existing(self):
        """
        Scan for existing JSON files in the watch directory.
        Useful when starting up to process any files that arrived while stopped.
        """
        logger.info(f"Scanning existing files in: {self.watch_path}")
        
        pattern = "**/*.json" if self.recursive else "*.json"
        count = 0
        
        for json_file in self.watch_path.glob(pattern):
            parsed = parse_json_file(str(json_file))
            if parsed:
                try:
                    self.on_file_detected(parsed)
                    count += 1
                except Exception as e:
                    logger.error(f"Error processing {json_file}: {e}")
        
        logger.info(f"Processed {count} existing files")
        return count


class WatcherService:
    """
    High-level service that manages the directory watcher
    and integrates with the database.
    """
    
    def __init__(self, db_session_factory):
        """
        Initialize the watcher service.
        
        Args:
            db_session_factory: Callable that returns a database session
        """
        self.db_session_factory = db_session_factory
        self.watcher: Optional[DirectoryWatcher] = None
        self._stats = {
            "files_processed": 0,
            "new_assets": 0,
            "updated_assets": 0,
            "errors": 0,
            "last_file": None,
            "started_at": None
        }
    
    def _handle_file(self, parsed_file: ParsedFile):
        """
        Handle a detected file by updating the database.
        """
        from database import Asset, BaselineSnapshot, Change, ChangeStatus
        from core import compare_configurations, compute_config_hash
        import json
        
        logger.info(f"Handling file: {parsed_file.filename} -> Asset: {parsed_file.asset_name}")
        
        db = self.db_session_factory()
        try:
            # Check if asset exists
            asset = db.query(Asset).filter(Asset.asset_name == parsed_file.asset_name).first()
            
            if not asset:
                # New asset - create it
                logger.info(f"New asset detected: {parsed_file.asset_name}")
                asset = Asset(
                    asset_name=parsed_file.asset_name,
                    fqdn=parsed_file.fqdn,
                    version=parsed_file.version
                )
                db.add(asset)
                db.flush()  # Get the ID
                
                # Create initial baseline snapshot
                snapshot = BaselineSnapshot(
                    asset_id=asset.id,
                    config_json=json.dumps(parsed_file.config),
                    config_hash=compute_config_hash(parsed_file.config),
                    source="file_watcher",
                    triggered_by="system",
                    filename=parsed_file.filename,
                    is_current_baseline=True,
                    promoted_at=datetime.utcnow(),
                    promoted_by="system"
                )
                db.add(snapshot)
                
                self._stats["new_assets"] += 1
            else:
                # Existing asset - compare and create pending changes
                logger.info(f"Existing asset updated: {parsed_file.asset_name}")
                
                # Get current baseline
                current_baseline = db.query(BaselineSnapshot).filter(
                    BaselineSnapshot.asset_id == asset.id,
                    BaselineSnapshot.is_current_baseline == True
                ).first()
                
                if current_baseline:
                    old_config = json.loads(current_baseline.config_json)
                    result = compare_configurations(old_config, parsed_file.config)
                    
                    if not result.is_identical:
                        # Create new snapshot (not promoted yet)
                        new_snapshot = BaselineSnapshot(
                            asset_id=asset.id,
                            config_json=json.dumps(parsed_file.config),
                            config_hash=result.new_hash,
                            source="file_watcher",
                            triggered_by="system",
                            filename=parsed_file.filename,
                            is_current_baseline=False
                        )
                        db.add(new_snapshot)
                        db.flush()
                        
                        # Create change records
                        for change in result.changes:
                            change_record = Change(
                                asset_id=asset.id,
                                field_path=change.path,
                                change_type=change.change_type.value,
                                old_value=json.dumps(change.old_value) if change.old_value else None,
                                new_value=json.dumps(change.new_value) if change.new_value else None,
                                items_added=json.dumps(change.items_added) if change.items_added else None,
                                items_removed=json.dumps(change.items_removed) if change.items_removed else None,
                                status=ChangeStatus.PENDING,
                                change_signature=change.signature,
                                old_snapshot_id=current_baseline.id,
                                new_snapshot_id=new_snapshot.id
                            )
                            db.add(change_record)
                        
                        logger.info(f"Created {len(result.changes)} pending changes for {parsed_file.asset_name}")
                
                # Update asset metadata
                asset.fqdn = parsed_file.fqdn or asset.fqdn
                asset.version = parsed_file.version or asset.version
                asset.updated_at = datetime.utcnow()
                
                self._stats["updated_assets"] += 1
            
            db.commit()
            self._stats["files_processed"] += 1
            self._stats["last_file"] = parsed_file.filename
            
        except Exception as e:
            logger.error(f"Error handling file {parsed_file.filename}: {e}")
            db.rollback()
            self._stats["errors"] += 1
            raise
        finally:
            db.close()
    
    def start(self, watch_path: str):
        """Start the watcher service."""
        if self.watcher and self.watcher.is_running():
            logger.warning("Watcher already running")
            return
        
        self.watcher = DirectoryWatcher(
            watch_path=watch_path,
            on_file_detected=self._handle_file
        )
        
        # Process existing files first
        self.watcher.scan_existing()
        
        # Start watching for new files
        self.watcher.start()
        self._stats["started_at"] = datetime.utcnow().isoformat()
        
        logger.info(f"Watcher service started on: {watch_path}")
    
    def stop(self):
        """Stop the watcher service."""
        if self.watcher:
            self.watcher.stop()
            self.watcher = None
            logger.info("Watcher service stopped")
    
    def get_stats(self) -> dict:
        """Get watcher statistics."""
        return {
            **self._stats,
            "is_running": self.watcher.is_running() if self.watcher else False
        }


# Standalone runner for testing
if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    def print_file(parsed: ParsedFile):
        print(f"Detected: {parsed.asset_name} from {parsed.filename}")
        print(f"  FQDN: {parsed.fqdn}")
        print(f"  Version: {parsed.version}")
        print(f"  Config keys: {list(parsed.config.keys())[:5]}...")
    
    watch_dir = os.environ.get("WATCH_DIR", "./test_watch")
    Path(watch_dir).mkdir(exist_ok=True)
    
    print(f"Watching: {watch_dir}")
    print("Drop JSON files in this directory to test...")
    print("Press Ctrl+C to stop")
    
    watcher = DirectoryWatcher(watch_dir, print_file)
    watcher.start()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping...")
        watcher.stop()
