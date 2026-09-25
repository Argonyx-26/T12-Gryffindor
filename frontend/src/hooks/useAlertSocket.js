import { useState, useEffect, useRef, useCallback } from 'react';

/**
 * useAlertSocket Custom React Hook
 * 
 * Purpose:
 * Connects to the backend WebSocket stream to receive real-time threat detection alerts.
 * 
 * Features:
 * 1. Reads WebSocket URL from import.meta.env.VITE_WS_URL, fallback to "ws://localhost:8000/ws/alerts".
 * 2. Parses incoming messages as JSON and prepends each new alert to the TOP of the alerts array (most recent first).
 * 3. Automatic reconnection: If disconnected, attempts reconnect every 3 seconds.
 * 4. Exposes connection state: "connected", "reconnecting", or "disconnected".
 * 5. Provides helper function to optimistically update alert status (e.g., dispatched or false_positive).
 */
const DEFAULT_WS_URL = 'ws://localhost:8000/ws/alerts';
const RECONNECT_DELAY_MS = 3000;

export function useAlertSocket(customUrl) {
  // Read WebSocket URL from environment variable or default
  const wsUrl = customUrl || import.meta.env.VITE_WS_URL || DEFAULT_WS_URL;

  // Real-time alert list in state (most recent at index 0)
  const [alerts, setAlerts] = useState([]);

  // Connection state: 'connected' | 'reconnecting' | 'disconnected'
  const [connectionStatus, setConnectionStatus] = useState('reconnecting');

  // Stable references for WebSocket instance and reconnect timer
  const socketRef = useRef(null);
  const reconnectTimerRef = useRef(null);
  const isMountedRef = useRef(true);

  /**
   * Helper function to normalize alert fields so they map cleanly to the UI,
   * handling both full Incident objects and lightweight alert notifications.
   */
  const normalizeAlert = useCallback((data) => {
    if (!data || typeof data !== 'object') return null;

    // Support both incident_id and id
    const incident_id = data.incident_id || data.id || `INC-${Date.now().toString().slice(-4)}`;
    
    // Severity mapping
    const severity = data.severity || (
      data.score >= 85 ? 'Critical' :
      data.score >= 70 ? 'High' :
      data.score >= 40 ? 'Medium' : 'Low'
    );

    // Timestamp formatting
    const rawTime = data.timestamp || data.first_ts || data.created_at;
    let formattedTimestamp = rawTime;
    if (rawTime) {
      try {
        const parsed = new Date(rawTime);
        if (!isNaN(parsed.getTime())) {
          formattedTimestamp = parsed.toLocaleTimeString('en-US', {
            hour12: false,
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit',
          }) + ' UTC';
        }
      } catch {
        formattedTimestamp = String(rawTime);
      }
    } else {
      formattedTimestamp = new Date().toLocaleTimeString('en-US', { hour12: false }) + ' UTC';
    }

    // Correlated events list
    let correlated_events = [];
    if (Array.isArray(data.correlated_events) && data.correlated_events.length > 0) {
      correlated_events = data.correlated_events;
    } else if (Array.isArray(data.event_ids) && data.event_ids.length > 0) {
      correlated_events = data.event_ids.map((id, idx) => `Correlated sensor hit #${idx + 1} (Event ID: ${id})`);
    } else if (Array.isArray(data.sources) && data.sources.length > 0) {
      correlated_events = data.sources.map(src => `Multimodal detection confirmed from [${src}] subsystem`);
    } else {
      correlated_events = [
        `Trigger event detected at ${formattedTimestamp}`,
        `Threat classification evaluated as ${severity}`
      ];
    }

    // Dynamic detection description wording based on number of sources
    let sourcesList = Array.isArray(data.sources)
      ? data.sources
      : (data.source_type ? [data.source_type] : []);

    let description = data.description;
    // Fallback extraction if sources array not provided but legacy description string is present
    if (sourcesList.length === 0 && typeof description === 'string') {
      const match = description.match(/(?:detection across:\s*)(.+)$/i);
      if (match) {
        sourcesList = match[1].split(',').map(s => s.trim()).filter(Boolean);
      }
    }

    if (sourcesList.length === 1) {
      description = `Single-source detection: ${sourcesList[0]}`;
    } else if (sourcesList.length >= 2) {
      description = `Corroborated multi-vector detection across: ${sourcesList.join(', ')}`;
    } else if (!description || description.startsWith('Corroborated multimodal detection across:') || description.startsWith('Corroborated multi-vector detection across:')) {
      description = 'Multi-vector physical/cyber anomaly detected by Gryffindor Sentinel.';
    }

    return {
      incident_id,
      zone_id: data.zone_id || data.zone || 'Sector Unknown',
      score: typeof data.score === 'number' ? Math.round(data.score) : Number(data.score) || 0,
      severity,
      timestamp: formattedTimestamp,
      status: data.status || 'open',
      description,
      camera_id: data.camera_id || (data.zone_id ? `CAM-${String(data.zone_id).replace(/\s+/g, '-').slice(0, 10).toUpperCase()}` : 'CAM-PRIMARY'),
      correlated_events,
      sources: sourcesList,
      ...data, // Preserve any additional backend fields
      // Ensure our dynamic description and normalized sources override any legacy backend description
      description,
      sources: sourcesList,
    };
  }, []);

  /**
   * Main connection management function
   */
  const connect = useCallback(() => {
    // Clear any existing reconnect timer
    if (reconnectTimerRef.current) {
      clearTimeout(reconnectTimerRef.current);
      reconnectTimerRef.current = null;
    }

    // Close any previous open or hung socket
    if (socketRef.current) {
      try {
        socketRef.current.onclose = null;
        socketRef.current.onerror = null;
        socketRef.current.close();
      } catch (e) {
        // ignore cleanup error
      }
      socketRef.current = null;
    }

    try {
      console.log(`[useAlertSocket] Connecting to ${wsUrl}...`);
      const socket = new WebSocket(wsUrl);
      socketRef.current = socket;

      socket.onopen = () => {
        if (!isMountedRef.current) return;
        console.log(`[useAlertSocket] Live WebSocket connection established to ${wsUrl}`);
        setConnectionStatus('connected');
      };

      socket.onmessage = (event) => {
        if (!isMountedRef.current) return;
        try {
          const rawData = JSON.parse(event.data);
          console.log('[useAlertSocket] Incoming alert payload:', rawData);

          // Handle both batch array of alerts or single alert object
          if (Array.isArray(rawData)) {
            const normalizedBatch = rawData.map(normalizeAlert).filter(Boolean);
            setAlerts((prevAlerts) => {
              // Add new alerts to the TOP, avoiding duplicate IDs
              const existingIds = new Set(prevAlerts.map(a => a.incident_id));
              const freshAlerts = normalizedBatch.filter(a => !existingIds.has(a.incident_id));
              return [...freshAlerts, ...prevAlerts];
            });
          } else if (rawData && typeof rawData === 'object') {
            const normalized = normalizeAlert(rawData);
            if (normalized) {
              setAlerts((prevAlerts) => {
                // If this alert already exists (e.g., status update broadcasted), update it
                const existingIndex = prevAlerts.findIndex(a => a.incident_id === normalized.incident_id);
                if (existingIndex !== -1) {
                  const updated = [...prevAlerts];
                  updated[existingIndex] = { ...updated[existingIndex], ...normalized };
                  return updated;
                }
                // Prepend new incoming alert to the TOP (most recent first)
                return [normalized, ...prevAlerts];
              });
            }
          }
        } catch (parseError) {
          console.error('[useAlertSocket] Failed to parse message JSON:', parseError, event.data);
        }
      };

      socket.onclose = (event) => {
        if (!isMountedRef.current) return;
        console.warn(`[useAlertSocket] Socket disconnected (code ${event.code}). Retrying in ${RECONNECT_DELAY_MS / 1000}s...`);
        setConnectionStatus('reconnecting');
        
        // Schedule auto-reconnect every 3 seconds
        reconnectTimerRef.current = setTimeout(() => {
          if (isMountedRef.current) {
            connect();
          }
        }, RECONNECT_DELAY_MS);
      };

      socket.onerror = (err) => {
        console.warn('[useAlertSocket] WebSocket error occurred:', err);
        // onerror is followed by onclose, which handles reconnect
      };

    } catch (connectionError) {
      console.error('[useAlertSocket] Failed to create WebSocket instance:', connectionError);
      setConnectionStatus('reconnecting');
      reconnectTimerRef.current = setTimeout(() => {
        if (isMountedRef.current) {
          connect();
        }
      }, RECONNECT_DELAY_MS);
    }
  }, [wsUrl, normalizeAlert]);

  // Establish connection on mount and cleanup on unmount
  useEffect(() => {
    isMountedRef.current = true;
    connect();

    return () => {
      isMountedRef.current = false;
      if (reconnectTimerRef.current) {
        clearTimeout(reconnectTimerRef.current);
      }
      if (socketRef.current) {
        socketRef.current.onclose = null;
        socketRef.current.onerror = null;
        socketRef.current.close();
      }
    };
  }, [connect]);

  /**
   * Optimistically update an alert's status in local state (e.g., 'dispatched' or 'false_positive')
   * for instant UI responsiveness when user clicks Dispatch or False Positive.
   */
  const updateAlertStatus = useCallback((incident_id, newStatus, extraFields = {}) => {
    setAlerts((prevAlerts) =>
      prevAlerts.map((alert) =>
        alert.incident_id === incident_id
          ? { ...alert, status: newStatus, ...extraFields }
          : alert
      )
    );
  }, []);

  return {
    alerts,
    setAlerts,
    connectionStatus,
    isConnected: connectionStatus === 'connected',
    isReconnecting: connectionStatus === 'reconnecting',
    wsUrl,
    updateAlertStatus,
  };
}

export default useAlertSocket;
