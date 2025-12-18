#!/usr/bin/env python3
"""
Database Migration Script: Migrate User fields to encrypted storage
Encrypts existing plaintext email and fullname fields using SecurityManager

Usage:
    python migrate_to_encrypted_fields.py
    python migrate_to_encrypted_fields.py --rollback  # To rollback changes
    python migrate_to_encrypted_fields.py --dry-run   # To preview changes
"""

import argparse
import sys
import traceback
from datetime import datetime

from app import create_app
from app.extensions import db
from app.models.user import User
from app.security import security_manager

def setup_app():
    """Initialize Flask application and database."""
    app = create_app()
    app.config['TESTING'] = True  # Disable rate limiting during migration

    with app.app_context():
        # Initialize security manager
        security_manager.init_app(app)
        return app

def backup_users_table():
    """Create a backup of the users table before migration."""
    backup_table = f"users_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

    try:
        # Create backup table with current user data
        db.engine.execute(f"""
            CREATE TABLE {backup_table} AS
            SELECT * FROM users
        """)
        print(f"✅ Backup created: {backup_table}")
        return backup_table
    except Exception as e:
        print(f"❌ Failed to create backup: {str(e)}")
        raise

def add_new_columns():
    """Add new encrypted columns to users table if they don't exist."""
    try:
        # Check if columns already exist
        result = db.engine.execute("""
            PRAGMA table_info(users)
        """).fetchall()

        existing_columns = [col[1] for col in result]

        columns_to_add = [
            ('email_encrypted', 'TEXT'),
            ('fullname_encrypted', 'TEXT'),
            ('email_search_hash', 'VARCHAR(64)'),
            ('encryption_migrated', 'BOOLEAN DEFAULT 0')
        ]

        for column_name, column_type in columns_to_add:
            if column_name not in existing_columns:
                db.engine.execute(f"ALTER TABLE users ADD COLUMN {column_name} {column_type}")
                print(f"✅ Added column: {column_name}")
            else:
                print(f"ℹ️  Column already exists: {column_name}")

        # Create index for email_search_hash if it doesn't exist
        try:
            db.engine.execute("""
                CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email_search_hash
                ON users(email_search_hash)
            """)
            print("✅ Created email_search_hash index")
        except Exception as e:
            print(f"⚠️  Index creation warning: {str(e)}")

    except Exception as e:
        print(f"❌ Failed to add columns: {str(e)}")
        raise

def migrate_users_to_encrypted(dry_run=False):
    """Migrate existing users from plaintext to encrypted fields."""
    users = User.query.filter_by(encryption_migrated=False).all()

    if not users:
        print("ℹ️  No users found requiring migration")
        return 0, 0

    success_count = 0
    failure_count = 0

    print(f"📋 Found {len(users)} users to migrate")

    for user in users:
        try:
            if dry_run:
                print(f"[DRY RUN] Would migrate user ID {user.id}: {user._email_legacy}")
                success_count += 1
                continue

            # Store original values for rollback capability
            original_email = user._email_legacy
            original_fullname = user._fullname_legacy

            if not original_email:
                print(f"⚠️  Skipping user {user.id}: No email found")
                continue

            # Migrate email
            user.email = original_email  # Uses the setter which encrypts

            # Migrate fullname
            if original_fullname:
                user.fullname = original_fullname  # Uses the setter which encrypts

            # Mark as migrated
            user.encryption_migrated = True

            # Verify encryption worked
            if user.email == original_email and user._email_encrypted:
                print(f"✅ Migrated user ID {user.id}: {original_email}")
                success_count += 1
            else:
                print(f"❌ Migration verification failed for user {user.id}")
                failure_count += 1
                continue

        except Exception as e:
            print(f"❌ Failed to migrate user ID {user.id}: {str(e)}")
            failure_count += 1
            # Continue with next user instead of failing completely

    if not dry_run:
        try:
            db.session.commit()
            print(f"💾 Committed changes to database")
        except Exception as e:
            db.session.rollback()
            print(f"❌ Failed to commit changes: {str(e)}")
            raise

    return success_count, failure_count

def rollback_migration(backup_table):
    """Rollback migration using backup table."""
    try:
        # Restore original table structure and data
        print(f"🔄 Rolling back from backup: {backup_table}")

        # Drop current table and restore from backup
        db.engine.execute("DROP TABLE users")
        db.engine.execute(f"ALTER TABLE {backup_table} RENAME TO users")

        print("✅ Rollback completed successfully")

    except Exception as e:
        print(f"❌ Rollback failed: {str(e)}")
        raise

def cleanup_legacy_fields():
    """Remove legacy plaintext fields after successful migration (optional)."""
    try:
        # Check if all users are migrated
        unmigrated_count = User.query.filter_by(encryption_migrated=False).count()

        if unmigrated_count > 0:
            print(f"⚠️  Cannot cleanup: {unmigrated_count} users still not migrated")
            return False

        # In SQLite, we cannot drop columns directly
        # This would require recreating the table
        print("ℹ️  Legacy field cleanup requires manual database operation")
        print("ℹ️  Legacy fields (email, fullname) can be removed manually if desired")

        return True

    except Exception as e:
        print(f"❌ Cleanup failed: {str(e)}")
        return False

def main():
    parser = argparse.ArgumentParser(description='Migrate user fields to encrypted storage')
    parser.add_argument('--rollback', action='store_true',
                       help='Rollback migration (requires backup table name)')
    parser.add_argument('--dry-run', action='store_true',
                       help='Preview migration without making changes')
    parser.add_argument('--backup-table', type=str,
                       help='Backup table name for rollback')
    parser.add_argument('--cleanup', action='store_true',
                       help='Remove legacy fields after migration')

    args = parser.parse_args()

    print("🔐 User Field Encryption Migration")
    print("=" * 50)

    try:
        # Setup application
        app = setup_app()

        with app.app_context():
            if args.rollback:
                if not args.backup_table:
                    print("❌ Rollback requires --backup-table parameter")
                    return 1

                rollback_migration(args.backup_table)
                return 0

            # Forward migration
            if not args.dry_run:
                # Create backup before making changes
                backup_table = backup_users_table()
                print(f"💾 Use --rollback --backup-table {backup_table} to undo")

            # Add new columns
            if not args.dry_run:
                add_new_columns()

            # Migrate users
            success, failure = migrate_users_to_encrypted(dry_run=args.dry_run)

            print("\n📊 Migration Summary:")
            print(f"✅ Successful migrations: {success}")
            print(f"❌ Failed migrations: {failure}")

            if args.dry_run:
                print("\nℹ️  This was a dry run - no changes made")
            elif failure == 0:
                print("\n🎉 Migration completed successfully!")

                if args.cleanup:
                    cleanup_legacy_fields()
            else:
                print(f"\n⚠️  Migration completed with {failure} failures")
                return 1

        return 0

    except KeyboardInterrupt:
        print("\n⚠️  Migration interrupted by user")
        return 1
    except Exception as e:
        print(f"\n❌ Migration failed: {str(e)}")
        print("\n🔍 Full traceback:")
        traceback.print_exc()
        return 1

if __name__ == '__main__':
    sys.exit(main())