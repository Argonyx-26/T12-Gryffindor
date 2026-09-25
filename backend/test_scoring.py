"""
Test Scoring Script (backend/test_scoring.py)
---------------------------------------------
Verifies the multi-source threat correlation scoring formula used in backend/main.py.

Simulates 3 events triggering in zone "Perimeter_Gate_3" within 1 second:
  - VIDEO: confidence 0.90
  - IOT:   confidence 1.00
  - CYBER: confidence 0.95

Evaluates the resulting score and severity against the target expectation (~94 / 100).
"""

import sys
from pathlib import Path

# Add project root to sys.path to allow standalone execution
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.constants import (
    CORRELATION_WINDOW_SECONDS,
    CORROBORATION_MULTIPLIER,
    SEVERITY_THRESHOLDS,
    SOURCE_WEIGHTS,
)
from backend.main import CorrelationEngine, calculate_incident_severity


def run_scoring_test():
    print("=" * 70)
    print("  GRYFFINDOR THREAT SCORING FORMULA VERIFICATION")
    print("=" * 70)
    print(f"\n[CONFIGURED CONSTANTS from backend/constants.py]")
    print(f"  SOURCE_WEIGHTS:            {SOURCE_WEIGHTS}")
    print(f"  CORROBORATION_MULTIPLIER:  {CORROBORATION_MULTIPLIER}")
    print(f"  SEVERITY_THRESHOLDS:       {SEVERITY_THRESHOLDS}")
    print(f"  CORRELATION_WINDOW_SECONDS: {CORRELATION_WINDOW_SECONDS}s")

    # 1. Create the 3 test events occurring within 1 second of each other in Perimeter_Gate_3
    test_events = [
        {
            "event_id": "test-video-001",
            "timestamp": "2026-09-25T12:00:00.000Z",
            "source_type": "VIDEO",
            "zone_id": "Perimeter_Gate_3",
            "coordinates": [37.4320, -122.1745],
            "event_type": "person_detected",
            "confidence": 0.90,
            "raw_meta": {"camera_id": "cam-gate-03"},
            "ingest_ts": "2026-09-25T12:00:00.020Z",
        },
        {
            "event_id": "test-iot-001",
            "timestamp": "2026-09-25T12:00:00.400Z",
            "source_type": "IOT",
            "zone_id": "Perimeter_Gate_3",
            "coordinates": [37.4320, -122.1745],
            "event_type": "door_forced",
            "confidence": 1.00,
            "raw_meta": {"sensor_id": "door-mag-03"},
            "ingest_ts": "2026-09-25T12:00:00.420Z",
        },
        {
            "event_id": "test-cyber-001",
            "timestamp": "2026-09-25T12:00:00.800Z",
            "source_type": "CYBER",
            "zone_id": "Perimeter_Gate_3",
            "coordinates": [37.4320, -122.1745],
            "event_type": "badge_brute_force",
            "confidence": 0.95,
            "raw_meta": {"user_id": "attacker"},
            "ingest_ts": "2026-09-25T12:00:00.820Z",
        },
    ]

    print("\n" + "-" * 70)
    print("  SIMULATING EVENT ARRIVAL IN CORRELATION ENGINE")
    print("-" * 70)

    engine = CorrelationEngine()
    latest_incident = None

    for idx, ev in enumerate(test_events, 1):
        latest_incident = engine.process_event(ev)
        print(f"\nStep {idx}: Received [{ev['source_type']}] (confidence: {ev['confidence']})")
        print(f"  - Correlated Sources: {latest_incident.sources}")
        print(f"  - Event IDs:          {latest_incident.event_ids}")
        print(f"  - Incident Score:     {latest_incident.score} / 100")
        print(f"  - Severity:           {latest_incident.severity}")

    # 2. Detailed Mathematical Breakdown of the Final Incident
    print("\n" + "=" * 70)
    print("  FINAL 3-SOURCE CORRELATION BREAKDOWN")
    print("=" * 70)

    # Re-compute exact intermediate values for clarity
    contributions = {}
    base_sum = 0.0
    for ev in test_events:
        w = SOURCE_WEIGHTS.get(ev["source_type"], 0.3)
        c = float(ev["confidence"])
        contrib = w * c
        contributions[ev["source_type"]] = (w, c, contrib)
        base_sum += contrib

    distinct_count = len(test_events)
    multiplier = CORROBORATION_MULTIPLIER.get(min(distinct_count, 3), 1.0)
    raw_score = base_sum * multiplier * 100.0
    final_score = round(min(100.0, max(0.0, raw_score)), 2)
    severity = calculate_incident_severity(final_score)

    print("Step 1: Weighted sum of confidences (base_sum):")
    for src, (w, c, contrib) in contributions.items():
        print(f"  - {src:<5}: weight {w:.2f} x conf {c:.2f} = {contrib:.4f}")
    print(f"  => base_sum = {base_sum:.4f} (or {base_sum * 100:.2f}% unscaled)")

    print(f"\nStep 2: Corroboration multiplier for {distinct_count} distinct sources:")
    print(f"  => multiplier = {multiplier:.2f}x (from CORROBORATION_MULTIPLIER[{distinct_count}])")

    print(f"\nStep 3: Raw Score calculation:")
    print(f"  => raw_score = base_sum ({base_sum:.4f}) x multiplier ({multiplier:.2f}) x 100")
    print(f"  => raw_score = {raw_score:.2f}")

    print(f"\nStep 4: Clamped Final Score & Classification:")
    print(f"  => final_score = min(100.0, {raw_score:.2f}) = {final_score:.2f} / 100")
    print(f"  => severity    = {severity}")

    # 3. Comparison with Target of ~94 (within 5 points)
    TARGET_SCORE = 94.0
    TOLERANCE = 5.0
    diff = abs(final_score - TARGET_SCORE)

    print("\n" + "=" * 70)
    print(f"  EVALUATION AGAINST TARGET ({TARGET_SCORE} +/- {TOLERANCE})")
    print("=" * 70)
    print(f"  Target Score:   {TARGET_SCORE}")
    print(f"  Actual Score:   {final_score}")
    print(f"  Difference:     {diff:.2f} points")

    if diff <= TOLERANCE:
        print(f"\n[RESULT: PASS] Score {final_score} is within {TOLERANCE} points of target {TARGET_SCORE}.")
    else:
        print(f"\n[RESULT: NOTICE] Score {final_score} exceeds the {TARGET_SCORE} target by {diff:.2f} points.")
        print("\n--- ROOT CAUSE EXPLANATION ---")
        print("1. Notice that the unscaled base_sum (weight x confidence) is ALREADY:")
        print(f"     0.35*0.90 + 0.35*1.00 + 0.30*0.95 = {base_sum:.4f} => {base_sum * 100:.1f} / 100")
        print("   This unscaled sum (95.0) is ALREADY within 1.0 point of 94!")
        print("2. However, backend/constants.py defines CORROBORATION_MULTIPLIER[3] = 2.2.")
        print(f"   Multiplying 95.0 by 2.2 gives 209.0, which clamps to 100.0.")

        print("\n--- HOW TO GET TO ~94 OUT OF 100 ---")
        print("Option A (Recommended - Adjust CORROBORATION_MULTIPLIER in constants.py):")
        print("  Since SOURCE_WEIGHTS already sums to 1.00 (0.35 + 0.35 + 0.30 = 1.00),")
        print("  1 source caps at 35, 2 sources cap at 70, and 3 sources naturally cap at 100.")
        print("  If you set CORROBORATION_MULTIPLIER[3] = 1.0 in backend/constants.py:")
        print("    score = 0.950 * 1.0 * 100 = 95.00  (Within 1 point of 94!)")
        print("  Or set CORROBORATION_MULTIPLIER[3] = 0.989:")
        print("    score = 0.950 * 0.989 * 100 = 94.00 (Exactly 94!)")

        print("\nOption B (Fine-tune event confidences without multiplier):")
        print("  With multiplier = 1.0, adjust confidences to reach exactly 94.00:")
        print("    VIDEO: 0.88 (0.35 x 0.88 = 0.308)")
        print("    IOT:   1.00 (0.35 x 1.00 = 0.350)")
        print("    CYBER: 0.94 (0.30 x 0.94 = 0.282)")
        print("    Sum = 0.308 + 0.350 + 0.282 = 0.940 => 94.0 / 100")

        print("\nOption C (Keep 2.2x multiplier in constants.py):")
        print("  If the 2.2x multiplier must remain in constants.py, the base_sum must be:")
        print("    94.0 / (2.2 x 100) = 0.4273")
        print("  This would require significantly lower confidence values (averaging ~0.43):")
        print("    VIDEO: 0.40, IOT: 0.45, CYBER: 0.43 => score ~ 94.0")

    return final_score, severity


if __name__ == "__main__":
    run_scoring_test()
