# Fiducia Quick Start Guide

**Fiducia** is a baseline configuration management system designed for CIP-010 compliance tracking. It monitors configuration changes across your infrastructure assets and provides a complete audit trail for regulatory compliance.

---

## Table of Contents

1. [Core Concepts](#core-concepts)
2. [Initial Setup](#initial-setup)
3. [Creating Your First Baseline](#creating-your-first-baseline)
4. [Understanding Change Detection](#understanding-change-detection)
5. [Reviewing Changes](#reviewing-changes)
6. [Ticket Number Hierarchy](#ticket-number-hierarchy)
7. [Investigation & Compliance Logic](#investigation--compliance-logic)
8. [Role-Based Access Control (RBAC)](#role-based-access-control-rbac)
9. [Settings Reference](#settings-reference)
10. [Reports & Audit Trail](#reports--audit-trail)

---

## Core Concepts

### What is a Baseline?
A baseline is a snapshot of an asset's configuration at a point in time. It represents the "approved" state of that asset. Any deviation from this baseline is flagged as a change requiring review.

### Asset States
| State | Description |
|-------|-------------|
| **Compliant** | Asset matches its approved baseline |
| **Pending Review** | Changes detected, awaiting admin review |
| **Investigation** | Changes under active investigation (35-day timer starts) |
| **Failed** | Investigation exceeded compliance window |
| **Retired** | Asset decommissioned, excluded from checks |

### Change Workflow
```
New Asset → Upload Config → Assign Group → Baseline Established
                                              ↓
                              Scheduled Check Detects Changes
                                              ↓
                              Changes Appear as "Pending Review"
                                              ↓
                    ┌─────────────────────────┼─────────────────────────┐
                    ↓                         ↓                         ↓
               APPROVE                   INVESTIGATE                  REJECT
          (Update Baseline)         (Start 35-day Timer)        (Keep Baseline)
```

---

## Initial Setup

### 1. Access the Application
Navigate to your Fiducia instance (default: `http://localhost:8000`).

### 2. Login
Use your administrator credentials. Default admin account is created during installation.

### 3. Configure Groups
Go to **Settings** and set up your asset groups:
- **Server** - Windows/Linux servers
- **Desktop** - Workstations
- **Network** - Switches, routers, firewalls
- **Telecom** - VoIP systems, PBX

Groups determine who can view and manage specific assets.

---

## Creating Your First Baseline

### Step 1: Prepare Your Configuration File
Export your asset's configuration as JSON. Example structure:

```json
{
  "fqdn": "server01.domain.local",
  "version": "10.0.19045.3803",
  "local_users": ["Administrator", "svc_backup"],
  "ports_services": [
    {"protocol": "tcp", "port": 22, "service": "SSH"},
    {"protocol": "tcp", "port": 443, "service": "HTTPS"}
  ],
  "syslog": [
    {"name": "LogServer", "ip_address": "10.0.0.50", "port": 514}
  ],
  "authentication_sources": [
    {"ip_address": "10.0.0.10", "protocol": "LDAP"}
  ]
}
```

### Step 2: Upload the Configuration
1. Go to the **Dashboard**
2. Use the upload area or watch folder
3. The asset appears in "Pending Assignment"

### Step 3: Assign to a Group
1. Click the asset in "Pending Assignment"
2. **Enter a ticket number** (required) - e.g., `CHG0012345`
3. Select the appropriate group
4. The initial baseline is now established

> **Important:** A ticket number is required when establishing the initial baseline. This creates an audit trail for compliance purposes.

---

## Understanding Change Detection

### Automatic Scheduled Checks
Fiducia runs automated compliance checks on configurable schedules (default: Day 1 and Day 15 of each month). When a check runs:

1. Current configuration is compared against the approved baseline
2. Differences are flagged as pending changes
3. Only actual additions/removals are detected (order changes are ignored)

### What Gets Compared
| Field | Comparison Method |
|-------|-------------------|
| Scalar values (strings, numbers) | Direct comparison |
| Arrays (ports, users, etc.) | Set-based comparison (order-insensitive) |
| Nested objects | Recursive deep comparison |

### Example: Port Changes
```
Baseline:  [port 22, port 443, port 80]
Current:   [port 80, port 443, port 22, port 8080]

Result: +port 8080 added (order change ignored)
```

---

## Reviewing Changes

### Where to Review
- **Dashboard** - Quick overview with approve/reject buttons
- **Changes Page** - Full detail view with all pending changes

### Review Actions

| Action | Effect |
|--------|--------|
| **Approve** | Accept the change, update the baseline |
| **Reject** | Deny the change, keep current baseline |
| **Investigate** | Start formal investigation, begin 35-day timer |

### Grouped Changes
Identical changes across multiple assets are automatically grouped. For example, if 10 servers all added the same new port, you can approve all 10 with one click.

---

## Ticket Number Hierarchy

Fiducia supports three levels of ticket assignment for audit documentation:

### Level 1: Global Ticket (Blue)
```
┌─────────────────────────────────────────────┐
│ 🔵 Global Ticket: [CHG0012345] [Apply All]  │
└─────────────────────────────────────────────┘
```
- Applies to ALL visible changes across all assets
- Use when one change ticket covers all modifications
- Click "Apply to All" to set the same ticket on everything

### Level 2: Per-Asset Ticket (Slate)
```
┌─────────────────────────────────────────────┐
│ Asset: server01.domain.local                │
│ 🔘 Asset Ticket: [CHG0012346] [Apply]       │
│   └─ Change 1: ports_services...            │
│   └─ Change 2: local_users...               │
└─────────────────────────────────────────────┘
```
- Applies to all changes for a specific asset
- Overrides the global ticket for that asset
- Use when different assets have different change tickets

### Level 3: Per-Field Ticket (Gray)
```
│   └─ Change 1: ports_services  [CHG0012347] │
```
- Applies to a single specific change
- Overrides both global and asset-level tickets
- Use for granular tracking when changes have different authorizations

### Hierarchy Priority
```
Per-Field Ticket > Per-Asset Ticket > Global Ticket
```

> **Note:** All change reviews require a ticket number. You cannot approve, reject, or investigate changes without providing a ticket.

---

## Investigation & Compliance Logic

### The 35-Day Compliance Window

When a change is marked for **Investigation**, a compliance timer begins:

```
Day 0:  Investigation opened
Day 1-34: ⏱️ Timer counting (Yellow status)
Day 35: ⚠️ Compliance deadline
Day 35+: 🔴 FAILED status (Red)
```

### Status Progression
```
PENDING → INVESTIGATION → APPROVED/REJECTED
                ↓
           (35 days pass)
                ↓
             FAILED
```

### Compliance Thresholds (Configurable)

| Days Remaining | Status Color | Urgency |
|----------------|--------------|---------|
| 15+ days | Green | Normal |
| 8-14 days | Yellow | Warning |
| 1-7 days | Orange | Critical |
| 0 or expired | Red | Failed |

### Auto-Investigation Behavior
If changes are not reviewed before the next scheduled check:
- **Option A:** Automatically move to Investigation (starts timer)
- **Option B:** Keep as Pending (configurable in Settings)

---

## Role-Based Access Control (RBAC)

### User Roles

| Role | Permissions |
|------|-------------|
| **Admin** | Full access: all assets, all groups, user management, settings |
| **Baseline Expert** | View/manage assets in assigned group only |

### Group-Based Visibility

```
Admin User (no group)
├── Can see: ALL assets
├── Can manage: ALL assets
└── Can access: Settings, User Management

Server Expert (group: server)
├── Can see: Server group assets only
├── Can manage: Server group assets only
└── Cannot access: Settings, other groups
```

### Creating Users

1. Go to **Settings → User Management**
2. Enter username, full name, password
3. Select role (Admin or Baseline Expert)
4. For Baseline Experts, they'll only see their assigned group's assets

### LDAP Integration
Fiducia supports LDAP authentication:
- Users authenticate against Active Directory
- Group membership can map to Fiducia groups
- Local accounts can coexist with LDAP accounts

---

## Settings Reference

### Watch Folder Configuration
| Setting | Description |
|---------|-------------|
| Watch Folder Path | Directory to monitor for new config files |
| File Pattern | Glob pattern for matching files (e.g., `*.json`) |
| Poll Interval | How often to check for new files |
| Archive Processed | Move processed files to archive folder |

### LDAP Authentication
| Setting | Description |
|---------|-------------|
| LDAP Server | Hostname or IP of LDAP server |
| LDAP Port | Port (389 for LDAP, 636 for LDAPS) |
| Use SSL | Enable TLS encryption |
| Bind DN | Service account for LDAP queries |
| Base DN | Search base for user lookups |
| User Filter | LDAP filter for finding users |

### Email Notifications
| Setting | Description |
|---------|-------------|
| SMTP Server | Mail server hostname |
| SMTP Port | Mail server port (25, 465, 587) |
| From Address | Sender email address |
| Alert Recipients | Comma-separated list of email addresses |
| Alert Types | Which events trigger emails |

### Syslog Forwarding
| Setting | Description |
|---------|-------------|
| Enable Syslog | Master toggle for syslog forwarding |
| Server | Syslog server hostname/IP |
| Port | Syslog port (514 UDP, 6514 TLS) |
| Protocol | UDP, TCP, or TLS |
| Facility | Syslog facility (LOCAL0-7) |
| Event Types | 26 configurable event types to forward |

### Compliance Settings
| Setting | Description |
|---------|-------------|
| Compliance Window | Days allowed for investigation (default: 35, set via COMPLIANCE_WINDOW_DAYS env var) |
| Check Schedule | Automated checks run on Day 1 and 15 by default (set via SCHEDULED_CHECK_DAYS env var) |

### Database Configuration
| Setting | Description |
|---------|-------------|
| Database URL | Connection string (SQLite, PostgreSQL, MySQL) |
| Pool Size | Connection pool size |
| Backup Schedule | Automated backup configuration |

---

## Reports & Audit Trail

### Available Reports

| Report Type | Description |
|-------------|-------------|
| **Approval Report** | Generated when changes are approved |
| **Rejection Report** | Generated when changes are rejected |
| **Investigation Report** | Generated when investigation opens |
| **Compliance Summary** | Overview of all asset states |
| **Ticket Impact Report** | Before/after view for a specific ticket |

### Viewing Reports
1. Reports are auto-generated during change review
2. Access historical reports from the **Reports** page
3. Export as text or print for documentation

### Audit Log
Every action is logged with:
- Timestamp
- User who performed the action
- Action type (approve, reject, investigate, etc.)
- Affected asset(s)
- Change details
- Ticket number

### User Activity Audit (Admin Only)
Administrators can review detailed activity history for any user:

1. Go to the **Compliance** page
2. Find the **User Audit** section in the tools row
3. Select a user from the dropdown (shows action counts)
4. Click **View** to open the audit modal

The audit modal displays:
- **Action Summary** - Color-coded badges showing counts by action type
- **Activity Log** - Chronological list of all user actions with:
  - Timestamp
  - Action type (color-coded)
  - Action details
  - Affected asset name

| Action Type | Color | Description |
|-------------|-------|-------------|
| create_asset | Green | New asset created |
| upload_changes | Blue | Configuration changes uploaded |
| change_approved | Green | Change approved |
| change_rejected | Red | Change rejected |
| bulk_investigation | Yellow | Multiple changes marked for investigation |
| finalize_baselines | Purple | Baselines finalized |
| delete_asset | Red | Asset deleted |
| rename_asset | Orange | Asset renamed |

### Ticket Impact Report
To see all changes associated with a specific ticket:
1. Go to the **Compliance** page
2. Enter the ticket number in **Ticket Search**
3. Click **Search** to view all changes linked to that ticket
4. View side-by-side before/after comparison

---

## Quick Reference

### Keyboard Shortcuts
| Key | Action |
|-----|--------|
| `D` | Go to Dashboard |
| `C` | Go to Changes |
| `A` | Go to Assets |
| `S` | Go to Settings |
| `?` | Show help |

### Common Tasks

**Add a new asset:**
1. Upload JSON config file
2. Enter ticket number
3. Assign to group

**Approve a change:**
1. Enter ticket number (or use global/asset ticket)
2. Click Approve button
3. Report auto-generates

**Start an investigation:**
1. Click Investigate button
2. Enter investigation notes
3. 35-day timer begins

**Rename an asset:**
1. Go to asset detail page
2. Click "Rename Asset"
3. Enter new name
4. Change appears for approval
5. Approve with ticket number

**Retire an asset:**
1. Go to asset detail page
2. Click "Retire Asset"
3. Enter retirement ticket
4. Asset excluded from future checks

**View user activity (Admin):**
1. Go to Compliance page
2. Select user from User Audit dropdown
3. Click "View" to see activity history
4. Review color-coded action log

**Compare two config files:**
1. Go to Compliance page
2. Click "Open Comparison Tool"
3. Upload before and after JSON files
4. View detected differences

---

## Troubleshooting

### "Ticket number is required"
All change reviews and initial baseline creations require a ticket number for audit compliance.

### Changes not appearing
- Verify the watch folder is configured correctly
- Check file matches the expected JSON format
- Ensure the asset has an established baseline

### Investigation timer not starting
The timer only starts when you click "Investigate". Pending changes do not have a timer.

### User can't see assets
- Verify user's group assignment matches the asset's group
- Admins can see all assets; Baseline Experts only see their group

---

## Support

For issues or feature requests:
- GitHub: https://github.com/mawzephyr/Fiducia
- Documentation: Built-in Help (? icon)

---

*Fiducia v4.0.6 - Infrastructure Baseline Management*
