# Fiducia v4.0.5
#!/usr/bin/env python3
"""One-time script to backfill ticket numbers for existing data."""
import sys
sys.path.insert(0, '/opt/boobytrap')

from database.connection import SessionLocal
from database.models import BaselineSnapshot, Change

def backfill_ticket_numbers(ticket_number: str):
    db = SessionLocal()
    try:
        # Update baseline snapshots
        snapshots_updated = db.query(BaselineSnapshot).filter(
            BaselineSnapshot.ticket_number == None
        ).update({"ticket_number": ticket_number})

        # Update changes
        changes_updated = db.query(Change).filter(
            Change.ticket_number == None
        ).update({"ticket_number": ticket_number})

        db.commit()
        print(f"Updated {snapshots_updated} baseline snapshots")
        print(f"Updated {changes_updated} changes")
        print(f"All records now have ticket_number = '{ticket_number}'")
    finally:
        db.close()

if __name__ == "__main__":
    ticket = sys.argv[1] if len(sys.argv) > 1 else "123456"
    backfill_ticket_numbers(ticket)
