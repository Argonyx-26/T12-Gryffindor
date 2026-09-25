"""Initial Schema for Gryffindor Sentinel (Phase 3C)

Revision ID: 001_initial_schema
Revises: 
Create Date: 2026-09-26 00:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = '001_initial_schema'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Events Table
    op.create_table(
        'events',
        sa.Column('event_id', sa.String(length=128), nullable=False),
        sa.Column('timestamp', sa.String(length=64), nullable=False),
        sa.Column('source_type', sa.String(length=32), nullable=False),
        sa.Column('zone_id', sa.String(length=128), nullable=False),
        sa.Column('coordinates', sa.JSON(), nullable=False),
        sa.Column('event_type', sa.String(length=128), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False),
        sa.Column('raw_meta', sa.JSON(), nullable=False),
        sa.Column('trace_id', sa.String(length=128), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('event_id')
    )
    op.create_index(op.f('ix_events_event_id'), 'events', ['event_id'], unique=False)
    op.create_index(op.f('ix_events_timestamp'), 'events', ['timestamp'], unique=False)
    op.create_index(op.f('ix_events_source_type'), 'events', ['source_type'], unique=False)
    op.create_index(op.f('ix_events_zone_id'), 'events', ['zone_id'], unique=False)
    op.create_index(op.f('ix_events_event_type'), 'events', ['event_type'], unique=False)
    op.create_index(op.f('ix_events_trace_id'), 'events', ['trace_id'], unique=False)

    # 2. Incidents Table
    op.create_table(
        'incidents',
        sa.Column('incident_id', sa.String(length=128), nullable=False),
        sa.Column('zone_id', sa.String(length=128), nullable=False),
        sa.Column('score', sa.Float(), nullable=False),
        sa.Column('severity', sa.String(length=32), nullable=False),
        sa.Column('sources', sa.JSON(), nullable=False),
        sa.Column('event_ids', sa.JSON(), nullable=False),
        sa.Column('first_ts', sa.String(length=64), nullable=False),
        sa.Column('dispatch_ts', sa.String(length=64), nullable=True),
        sa.Column('latency_ms', sa.Float(), nullable=False),
        sa.Column('status', sa.String(length=32), nullable=False),
        sa.Column('trace_id', sa.String(length=128), nullable=True),
        sa.Column('explanation', sa.Text(), nullable=True),
        sa.Column('contributing_factors', sa.JSON(), nullable=True),
        sa.Column('score_breakdown', sa.JSON(), nullable=True),
        sa.Column('timeline', sa.JSON(), nullable=True),
        sa.Column('recommendations', sa.JSON(), nullable=True),
        sa.Column('acknowledged_ts', sa.String(length=64), nullable=True),
        sa.Column('resolved_ts', sa.String(length=64), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('incident_id')
    )
    op.create_index(op.f('ix_incidents_incident_id'), 'incidents', ['incident_id'], unique=False)
    op.create_index(op.f('ix_incidents_zone_id'), 'incidents', ['zone_id'], unique=False)
    op.create_index(op.f('ix_incidents_severity'), 'incidents', ['severity'], unique=False)
    op.create_index(op.f('ix_incidents_first_ts'), 'incidents', ['first_ts'], unique=False)
    op.create_index(op.f('ix_incidents_status'), 'incidents', ['status'], unique=False)
    op.create_index(op.f('ix_incidents_trace_id'), 'incidents', ['trace_id'], unique=False)
    op.create_index(op.f('ix_incidents_updated_at'), 'incidents', ['updated_at'], unique=False)

    # 3. IncidentEvents Junction Table
    op.create_table(
        'incident_events',
        sa.Column('incident_id', sa.String(length=128), nullable=False),
        sa.Column('event_id', sa.String(length=128), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['event_id'], ['events.event_id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['incident_id'], ['incidents.incident_id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('incident_id', 'event_id')
    )
    op.create_index(op.f('ix_incident_events_event_id'), 'incident_events', ['event_id'], unique=False)
    op.create_index(op.f('ix_incident_events_incident_id'), 'incident_events', ['incident_id'], unique=False)

    # 4. Behavioral Baselines Table
    op.create_table(
        'behavioral_baselines',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('zone_id', sa.String(length=128), nullable=False),
        sa.Column('source_type', sa.String(length=32), nullable=False),
        sa.Column('event_type', sa.String(length=128), nullable=False),
        sa.Column('time_bucket', sa.Integer(), nullable=False),
        sa.Column('baseline_rate', sa.Float(), nullable=False),
        sa.Column('observation_count', sa.Integer(), nullable=False),
        sa.Column('last_updated', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('zone_id', 'source_type', 'event_type', 'time_bucket', name='uq_baseline_bucket')
    )
    op.create_index(op.f('ix_behavioral_baselines_event_type'), 'behavioral_baselines', ['event_type'], unique=False)
    op.create_index(op.f('ix_behavioral_baselines_source_type'), 'behavioral_baselines', ['source_type'], unique=False)
    op.create_index(op.f('ix_behavioral_baselines_time_bucket'), 'behavioral_baselines', ['time_bucket'], unique=False)
    op.create_index(op.f('ix_behavioral_baselines_zone_id'), 'behavioral_baselines', ['zone_id'], unique=False)

    # 5. Audit Logs Table
    op.create_table(
        'audit_logs',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('timestamp', sa.String(length=64), nullable=False),
        sa.Column('action', sa.String(length=64), nullable=False),
        sa.Column('incident_id', sa.String(length=128), nullable=True),
        sa.Column('details', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_audit_logs_action'), 'audit_logs', ['action'], unique=False)
    op.create_index(op.f('ix_audit_logs_incident_id'), 'audit_logs', ['incident_id'], unique=False)
    op.create_index(op.f('ix_audit_logs_timestamp'), 'audit_logs', ['timestamp'], unique=False)


def downgrade() -> None:
    op.drop_table('audit_logs')
    op.drop_table('behavioral_baselines')
    op.drop_table('incident_events')
    op.drop_table('incidents')
    op.drop_table('events')
