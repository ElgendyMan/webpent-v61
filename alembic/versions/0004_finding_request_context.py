"""persist normalized finding request context

Revision ID: 0004_finding_request_context
Create Date: 2026-08-20

V72 qualification: preserve the request method, redacted form data, and
selected parameter used by validators.  These fields are evidence metadata;
they do not promote a finding and remain subject to the causal/negative-control
proof gates.
"""
from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0004_finding_request_context"
down_revision = "0003_shared_reauth_vault"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add request-context columns to the findings table."""
    op.add_column(
        "findings",
        sa.Column("request_method", sa.Text, nullable=False, server_default="GET"),
    )
    op.add_column("findings", sa.Column("request_data", sa.Text))
    op.add_column("findings", sa.Column("target_param", sa.Text))


def downgrade() -> None:
    """Remove V72 request-context columns."""
    op.drop_column("findings", "target_param")
    op.drop_column("findings", "request_data")
    op.drop_column("findings", "request_method")
