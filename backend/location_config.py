"""
backend/location_config.py
Central Location Configuration & Location Resolution Engine for Gryffindor Sentinel.
Maps Cameras, IoT Sensors, Cyber Systems, and Zone Polygons to geospatial coordinates.
"""

from typing import Dict, Any, List, Optional, Tuple

# Demo Campus Center Coordinates: Stanford / Silicon Valley Security Perimeter
SITE_ID = "campus-main"
SITE_NAME = "Gryffindor Central Operations Campus"
DEFAULT_LATITUDE = 37.4282
DEFAULT_LONGITUDE = -122.1688

# Master Zone Catalog with Polygons & Geometries
ZONES_CATALOG: Dict[str, Dict[str, Any]] = {
    "Server_Room": {
        "zone_id": "Server_Room",
        "zone_name": "Central Server & Data Facility",
        "site_id": SITE_ID,
        "latitude": 37.4282,
        "longitude": -122.1688,
        "zone_weight": 1.5,
        "polygon": [
            [37.4286, -122.1692],
            [37.4286, -122.1684],
            [37.4278, -122.1684],
            [37.4278, -122.1692]
        ]
    },
    "Perimeter_Gate_3": {
        "zone_id": "Perimeter_Gate_3",
        "zone_name": "North Campus Perimeter Gate 3",
        "site_id": SITE_ID,
        "latitude": 37.4320,
        "longitude": -122.1745,
        "zone_weight": 1.3,
        "polygon": [
            [37.4325, -122.1750],
            [37.4325, -122.1740],
            [37.4315, -122.1740],
            [37.4315, -122.1750]
        ]
    },
    "Parking_Lot": {
        "zone_id": "Parking_Lot",
        "zone_name": "East Campus Visitor Parking Lot",
        "site_id": SITE_ID,
        "latitude": 37.4255,
        "longitude": -122.1620,
        "zone_weight": 0.8,
        "polygon": [
            [37.4260, -122.1625],
            [37.4260, -122.1615],
            [37.4250, -122.1615],
            [37.4250, -122.1625]
        ]
    },
    "Parking_Lot_B": {
        "zone_id": "Parking_Lot_B",
        "zone_name": "West Campus Secondary Parking Lot",
        "site_id": SITE_ID,
        "latitude": 37.4250,
        "longitude": -122.1630,
        "zone_weight": 0.8,
        "polygon": [
            [37.4255, -122.1635],
            [37.4255, -122.1625],
            [37.4245, -122.1625],
            [37.4245, -122.1635]
        ]
    }
}

# Fixed Camera Catalog
CAMERAS_CATALOG: Dict[str, Dict[str, Any]] = {
    "CAM-01": {
        "camera_id": "CAM-01",
        "name": "CCTV Perimeter North Gate",
        "zone_id": "Perimeter_Gate_3",
        "zone_name": "North Campus Perimeter Gate 3",
        "latitude": 37.4320,
        "longitude": -122.1745,
        "status": "online"
    },
    "CAM-02": {
        "camera_id": "CAM-02",
        "name": "CCTV East Parking Lot",
        "zone_id": "Parking_Lot",
        "zone_name": "East Campus Visitor Parking Lot",
        "latitude": 37.4255,
        "longitude": -122.1620,
        "status": "online"
    },
    "CAM-03": {
        "camera_id": "CAM-03",
        "name": "CCTV Server Vault Interior",
        "zone_id": "Server_Room",
        "zone_name": "Central Server & Data Facility",
        "latitude": 37.4282,
        "longitude": -122.1688,
        "status": "online"
    }
}

# Fixed IoT Sensors Catalog
SENSORS_CATALOG: Dict[str, Dict[str, Any]] = {
    "IOT-01": {
        "sensor_id": "IOT-01",
        "name": "Server Room Access Door Contact",
        "zone_id": "Server_Room",
        "zone_name": "Central Server & Data Facility",
        "latitude": 37.4282,
        "longitude": -122.1688,
        "status": "online"
    },
    "IOT-02": {
        "sensor_id": "IOT-02",
        "name": "Gate 3 Infrared Motion Detector",
        "zone_id": "Perimeter_Gate_3",
        "zone_name": "North Campus Perimeter Gate 3",
        "latitude": 37.4320,
        "longitude": -122.1745,
        "status": "online"
    }
}

# Cyber Infrastructure Node Catalog
CYBER_NODES_CATALOG: Dict[str, Dict[str, Any]] = {
    "CYBER-01": {
        "system_id": "CYBER-01",
        "name": "Active Directory Auth Controller",
        "zone_id": "Server_Room",
        "zone_name": "Central Server & Data Facility",
        "location_type": "logical",
        "mapped_physical_zone": "Server_Room",
        "latitude": 37.4282,
        "longitude": -122.1688
    }
}


def get_event_location(event_obj: Any) -> Dict[str, Any]:
    """
    Extracts or resolves structured location metadata from an Event instance or dict.
    Returns location dict with site_id, zone_id, zone_name, coordinates, location_type, and asset_id.
    """
    raw_meta = getattr(event_obj, "raw_meta", {}) or {}
    zone_id = getattr(event_obj, "zone_id", "Server_Room") or "Server_Room"
    source_type = getattr(event_obj, "source_type", "IOT")
    coords = getattr(event_obj, "coordinates", [0.0, 0.0]) or [0.0, 0.0]

    camera_id = raw_meta.get("camera_id") or raw_meta.get("cctv_id")
    sensor_id = raw_meta.get("sensor_id") or raw_meta.get("iot_id")
    cyber_id = raw_meta.get("cyber_id") or raw_meta.get("syslog_id") or raw_meta.get("system_id")

    zone_info = ZONES_CATALOG.get(zone_id, ZONES_CATALOG["Server_Room"])
    lat = coords[0] if len(coords) >= 2 and coords[0] != 0.0 else zone_info["latitude"]
    lng = coords[1] if len(coords) >= 2 and coords[1] != 0.0 else zone_info["longitude"]

    location_type = "physical"
    if source_type == "CYBER" and not raw_meta.get("has_gps", False):
        location_type = "logical"

    return {
        "site_id": SITE_ID,
        "site_name": SITE_NAME,
        "zone_id": zone_id,
        "zone_name": zone_info.get("zone_name", zone_id),
        "location_type": location_type,
        "latitude": lat,
        "longitude": lng,
        "camera_id": camera_id if source_type == "VIDEO" else None,
        "sensor_id": sensor_id if source_type == "IOT" else None,
        "cyber_id": cyber_id if source_type == "CYBER" else None,
    }


def get_incident_primary_location(
    incident_obj: Any,
    correlated_events: List[Any]
) -> Dict[str, Any]:
    """
    Deterministically computes primary location and asset breakdowns for an Incident.
    Priority:
    1. Highest confidence VIDEO or IOT event location
    2. First physical event location
    3. Zone location
    4. Logical location
    """
    affected_zones = sorted(list({getattr(ev, "zone_id", "") for ev in correlated_events if getattr(ev, "zone_id", "")}))
    if not affected_zones and hasattr(incident_obj, "zone_id"):
        affected_zones = [incident_obj.zone_id]

    contributing_cameras = []
    contributing_iot = []
    contributing_cyber = []

    physical_events = []
    for ev in correlated_events:
        src = getattr(ev, "source_type", "")
        raw = getattr(ev, "raw_meta", {}) or {}
        if src == "VIDEO":
            cam = raw.get("camera_id") or "CAM-01"
            if cam not in contributing_cameras:
                contributing_cameras.append(cam)
            physical_events.append(ev)
        elif src == "IOT":
            sns = raw.get("sensor_id") or "IOT-01"
            if sns not in contributing_iot:
                contributing_iot.append(sns)
            physical_events.append(ev)
        elif src == "CYBER":
            cyb = raw.get("cyber_id") or raw.get("system_id") or "CYBER-01"
            if cyb not in contributing_cyber:
                contributing_cyber.append(cyb)

    # Select best primary event
    best_event = None
    if physical_events:
        best_event = max(physical_events, key=lambda e: getattr(e, "confidence", 0.0))
    elif correlated_events:
        best_event = correlated_events[0]

    if best_event:
        primary_loc = get_event_location(best_event)
    else:
        z_id = getattr(incident_obj, "zone_id", "Server_Room")
        z_info = ZONES_CATALOG.get(z_id, ZONES_CATALOG["Server_Room"])
        primary_loc = {
            "site_id": SITE_ID,
            "site_name": SITE_NAME,
            "zone_id": z_id,
            "zone_name": z_info["zone_name"],
            "location_type": "physical",
            "latitude": z_info["latitude"],
            "longitude": z_info["longitude"],
            "camera_id": contributing_cameras[0] if contributing_cameras else None,
            "sensor_id": contributing_iot[0] if contributing_iot else None,
            "cyber_id": contributing_cyber[0] if contributing_cyber else None,
        }

    return {
        "primary_location": primary_loc,
        "affected_zones": affected_zones,
        "contributing_cameras": contributing_cameras,
        "contributing_iot": contributing_iot,
        "contributing_cyber": contributing_cyber,
    }


def get_all_locations_payload() -> Dict[str, Any]:
    """
    Returns full catalog payload for GET /locations endpoint.
    """
    return {
        "site": {
            "site_id": SITE_ID,
            "site_name": SITE_NAME,
            "latitude": DEFAULT_LATITUDE,
            "longitude": DEFAULT_LONGITUDE,
            "zoom": 16,
        },
        "zones": list(ZONES_CATALOG.values()),
        "cameras": list(CAMERAS_CATALOG.values()),
        "sensors": list(SENSORS_CATALOG.values()),
        "cyber_nodes": list(CYBER_NODES_CATALOG.values()),
    }
