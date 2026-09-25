"""
Context-Aware Threat Scoring Engine & Explainability System
Provides intelligent contextual risk evaluation, score breakdown, human-readable explanations,
actionable response recommendations, and structured incident timelines.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from backend.constants import (
    CORROBORATION_MULTIPLIER,
    DEFAULT_EVENT_RISK,
    DEFAULT_SHIFT_HOURS,
    EVENT_RISK_PROFILES,
    MAX_REPEATED_BOOST,
    OFF_SHIFT_MULTIPLIER,
    REPEATED_EVENT_BOOST,
    RESTRICTED_ZONE_MULTIPLIER,
    SEVERITY_THRESHOLDS,
    SOURCE_WEIGHTS,
)
from backend.models import Event, Incident


def is_off_shift(timestamp_str: str, shift_hours: Tuple[int, int] = DEFAULT_SHIFT_HOURS) -> bool:
    """Checks if timestamp falls outside normal working hours."""
    try:
        dt = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
        hour = dt.hour
        start, end = shift_hours
        return not (start <= hour < end)
    except Exception:
        return False


class ScoringEngine:
    """
    Evaluates correlated multi-source events with contextual intelligence.
    """

    @classmethod
    def calculate_contextual_score(
        cls,
        correlated_events: List[Event],
        zone_info: Dict[str, Any],
    ) -> Tuple[float, Dict[str, Any], List[str], str, List[str]]:
        """
        Calculates threat score, score breakdown, contributing factors, explanation,
        and response recommendations.
        """
        if not correlated_events:
            return 0.0, {}, [], "No events provided.", []

        distinct_sources = sorted(list({ev.source_type for ev in correlated_events}))
        num_sources = len(distinct_sources)
        corr_multiplier = CORROBORATION_MULTIPLIER.get(min(num_sources, 3), 1.0)

        zone_weight = float(zone_info.get("zone_weight", 1.0))
        shift_hours = zone_info.get("shift_hours", DEFAULT_SHIFT_HOURS)

        modality_scores: Dict[str, float] = {}
        contributing_factors: List[str] = []

        for src in distinct_sources:
            src_events = [ev for ev in correlated_events if ev.source_type == src]
            weight = SOURCE_WEIGHTS.get(src, 0.30)

            # Find peak event risk factor within this modality
            best_event_contrib = 0.0
            for ev in src_events:
                risk_profile = EVENT_RISK_PROFILES.get(src, {}).get(ev.event_type, DEFAULT_EVENT_RISK)
                eff_conf = max(0.0, min(1.0, ev.confidence))

                # Context multipliers
                context_mult = 1.0

                # Off-shift door or motion access
                off_shift = is_off_shift(ev.timestamp, shift_hours) or ev.raw_meta.get("off_shift", False)
                if off_shift and ev.event_type in ["door_open", "motion", "off_shift_access", "forced_entry", "sensor_tamper"]:
                    context_mult *= OFF_SHIFT_MULTIPLIER
                    factor_msg = f"Off-shift physical activity ({ev.event_type}) in {ev.zone_id}"
                    if factor_msg not in contributing_factors:
                        contributing_factors.append(factor_msg)

                # Restricted zone entry
                in_restricted = ev.raw_meta.get("restricted_zone", False) or ev.event_type in ["restricted_zone_entry", "tripwire_crossed"]
                if in_restricted:
                    context_mult *= RESTRICTED_ZONE_MULTIPLIER
                    factor_msg = f"Restricted zone breach ({ev.event_type}) in {ev.zone_id}"
                    if factor_msg not in contributing_factors:
                        contributing_factors.append(factor_msg)

                # Cyber threat intelligence context
                if src == "CYBER":
                    fail_count = ev.raw_meta.get("failed_attempts") or ev.raw_meta.get("login_count") or 1
                    if ev.event_type == "login_spike" or fail_count > 5:
                        context_mult *= 1.25
                        factor_msg = f"Cyber brute-force anomaly detected ({ev.event_type})"
                        if factor_msg not in contributing_factors:
                            contributing_factors.append(factor_msg)

                if ev.event_type not in EVENT_RISK_PROFILES.get(src, {}):
                    factor_msg = f"Unclassified event type '{ev.event_type}' processed safely with fallback risk profile"
                    if factor_msg not in contributing_factors:
                        contributing_factors.append(factor_msg)

                event_contrib = eff_conf * risk_profile * context_mult * weight * 100.0
                if event_contrib > best_event_contrib:
                    best_event_contrib = event_contrib

            # Repeated activity boost per modality
            if len(src_events) > 1:
                repeat_count = len(src_events)
                repeat_boost = min(MAX_REPEATED_BOOST, 1.0 + (repeat_count - 1) * (REPEATED_EVENT_BOOST - 1.0))
                best_event_contrib *= repeat_boost
                factor_msg = f"Repeated suspicious {src} activity ({repeat_count} hits)"
                if factor_msg not in contributing_factors:
                    contributing_factors.append(factor_msg)

            modality_scores[src] = round(best_event_contrib, 2)

<<<<<<< HEAD
        # ----------------------------------------------------------------------
        # Phase 3B Temporal & Behavioral Intelligence Layer
        # ----------------------------------------------------------------------
        from backend.temporal_engine import (
            SequencePatternEngine,
            BurstDetector,
            BehavioralBaselineEngine,
            calculate_recency_factor,
            calculate_temporal_pattern_bonus,
            calculate_behavioral_anomaly_bonus,
        )

        matched_patterns = SequencePatternEngine.evaluate_sequence_patterns(correlated_events)
        detected_bursts = BurstDetector.detect_bursts(correlated_events)
        
        # Calculate zone statistics and off-shift state
        ref_timestamp = correlated_events[-1].timestamp if correlated_events else datetime.now(timezone.utc).isoformat()
        off_shift_flag = any(is_off_shift(ev.timestamp, shift_hours) or bool(ev.raw_meta.get("off_shift", False)) for ev in correlated_events)
        zone_stats = BehavioralBaselineEngine.compute_zone_statistics(correlated_events, zone_info.get("zone_id", correlated_events[0].zone_id))
        anomaly_ratio = zone_stats.get("anomaly_ratio", 1.0)

        # Compute bounded bonus terms
        pattern_bonus = calculate_temporal_pattern_bonus(matched_patterns)
        anomaly_bonus = calculate_behavioral_anomaly_bonus(anomaly_ratio, off_shift_flag)
        recency_factor = calculate_recency_factor(correlated_events[0].timestamp, ref_timestamp)

        # Document factors
        if matched_patterns:
            for pat in matched_patterns:
                factor_msg = f"Temporal sequence pattern matched: '{pat['pattern_name']}' (conf={pat['confidence']})"
                if factor_msg not in contributing_factors:
                    contributing_factors.append(factor_msg)

        if detected_bursts:
            for bst in detected_bursts:
                factor_msg = bst["description"]
                if factor_msg not in contributing_factors:
                    contributing_factors.append(factor_msg)

        if anomaly_ratio > 1.5:
            factor_msg = f"Elevated zone event frequency detected ({zone_stats['events_per_minute']} events/min vs baseline {zone_stats['baseline_events_per_minute']})"
            if factor_msg not in contributing_factors:
                contributing_factors.append(factor_msg)

        base_sum = sum(modality_scores.values())
        raw_scaled = (base_sum + pattern_bonus + anomaly_bonus) * corr_multiplier * (zone_weight / 1.5)
=======
        base_sum = sum(modality_scores.values())
        raw_scaled = base_sum * corr_multiplier * (zone_weight / 1.5)
>>>>>>> 36887e41dc7a1241b44edbd31892a5d1be9a39c0
        final_score = round(min(100.0, max(0.0, raw_scaled)), 2)

        if num_sources > 1:
            factor_msg = f"{num_sources} independent source modalities corroborated the threat ({', '.join(distinct_sources)})"
            if factor_msg not in contributing_factors:
                contributing_factors.append(factor_msg)

        if zone_weight >= 1.5:
            factor_msg = f"High criticality zone modifier applied ({zone_info.get('name', 'Zone')} weight={zone_weight})"
            if factor_msg not in contributing_factors:
                contributing_factors.append(factor_msg)

<<<<<<< HEAD
        # Generate XAI Plain English Explanation
        if matched_patterns and num_sources >= 2:
            pat_names = ", ".join([p["pattern_name"] for p in matched_patterns])
            explanation = (
                f"Threat score escalated because a restricted-zone VIDEO event was followed by off-shift IOT access "
                f"and abnormal CYBER activity within the correlation window (Matched sequence: {pat_names})."
            )
        else:
            explanation = (
                f"Correlated {len(correlated_events)} security event(s) across {num_sources} modality source(s) "
                f"({', '.join(distinct_sources)}) in zone '{zone_info.get('name', correlated_events[0].zone_id)}' "
                f"with corroboration multiplier {corr_multiplier}x."
            )

        # Build score breakdown dict
        score_breakdown = {
            "base_score": round(base_sum, 2),
            "modality_contributions": modality_scores,
            "corroboration_multiplier": corr_multiplier,
            "zone_weight": zone_weight,
            "temporal_pattern_bonus": pattern_bonus,
            "behavioral_anomaly_bonus": anomaly_bonus,
            "recency_factor": recency_factor,
=======
        # Generate human-readable explanation
        explanation = (
            f"Correlated {len(correlated_events)} security event(s) across {num_sources} modality source(s) "
            f"({', '.join(distinct_sources)}) in zone '{zone_info.get('name', correlated_events[0].zone_id)}' "
            f"with corroboration multiplier {corr_multiplier}x."
        )

        # Build score breakdown dict
        score_breakdown = {
            "modality_contributions": modality_scores,
            "corroboration_multiplier": corr_multiplier,
            "zone_weight": zone_weight,
            "raw_base_sum": round(base_sum, 2),
>>>>>>> 36887e41dc7a1241b44edbd31892a5d1be9a39c0
            "final_score": final_score,
        }

        # Generate recommendations
        recommendations = cls.generate_recommendations(final_score, distinct_sources, correlated_events)

        return final_score, score_breakdown, contributing_factors, explanation, recommendations

    @classmethod
    def generate_recommendations(
        cls,
        score: float,
        sources: List[str],
        events: List[Event],
    ) -> List[str]:
        """Generates safe, non-executing operational response recommendations."""
        recs = []
        if score < 40.0:
            recs.append("Log event for routine auditing; no immediate dispatch required.")
            return recs

        recs.append("Verify associated CCTV live stream and historical playback clips.")

        if "IOT" in sources:
            recs.append("Review physical access-control door logs and perimeter sensor status.")

        if "CYBER" in sources:
            recs.append("Audit user authentication logs and temporarily isolate suspicious user sessions.")

        if "VIDEO" in sources:
            recs.append("Confirm visual target classification and cross-reference tripwire bounding boxes.")

        if score >= 80.0:
            recs.append("Dispatch on-duty security tactical team immediately to verify perimeter breach.")
            recs.append("Notify shift supervisor and log incident details for formal post-incident review.")

        return recs

    @classmethod
    def build_timeline(
        cls,
        existing_timeline: List[Dict[str, Any]],
        correlated_events: List[Event],
        incident_id: str,
        score: float,
        severity: str,
    ) -> List[Dict[str, Any]]:
        """Constructs or appends structured timeline milestones without duplicates."""
        existing_event_ids = {t.get("event_id") for t in existing_timeline if t.get("event_id")}
        new_timeline = list(existing_timeline)

        for ev in sorted(correlated_events, key=lambda e: e.timestamp):
            if ev.event_id in existing_event_ids:
                continue

            entry = {
                "timestamp": ev.timestamp,
                "event_id": ev.event_id,
                "source": ev.source_type,
                "event_type": ev.event_type,
                "description": f"[{ev.source_type}] {ev.event_type.replace('_', ' ').title()} detected (conf: {ev.confidence:.2f})",
            }
            new_timeline.append(entry)
            existing_event_ids.add(ev.event_id)

<<<<<<< HEAD
        from backend.temporal_engine import SequencePatternEngine
        matched_patterns = SequencePatternEngine.evaluate_sequence_patterns(correlated_events)
        for pat in matched_patterns:
            pat_msg = f"SEQUENCE: Pattern matched '{pat['pattern_name']}'"
            if not any(t.get("description") == pat_msg for t in new_timeline):
                new_timeline.append({
                    "timestamp": sorted(correlated_events, key=lambda e: e.timestamp)[-1].timestamp,
                    "source": "TEMPORAL",
                    "event_type": "pattern_matched",
                    "description": pat_msg,
                })

=======
>>>>>>> 36887e41dc7a1241b44edbd31892a5d1be9a39c0
        now_utc = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        engine_entry_msg = f"ENGINE: Threat score evaluated as {score} ({severity})"
        if not any(t.get("description") == engine_entry_msg for t in new_timeline):
            new_timeline.append({
                "timestamp": now_utc,
                "source": "ENGINE",
                "event_type": "threat_evaluated",
                "description": engine_entry_msg,
            })

<<<<<<< HEAD
        # Ensure timeline remains strictly chronological by timestamp
        return sorted(new_timeline, key=lambda x: str(x.get("timestamp", "")))
=======
        return new_timeline
>>>>>>> 36887e41dc7a1241b44edbd31892a5d1be9a39c0
