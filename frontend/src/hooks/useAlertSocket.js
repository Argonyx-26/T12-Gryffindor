import { useState, useEffect, useRef, useCallback } from 'react';
import { INITIAL_ALERTS } from '../data/mockAlerts';

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
const DEFAULT_API_URL = 'http://localhost:8000';
const RECONNECT_DELAY_MS = 3000;

/**
 * Helper function to normalize alert fields so they map cleanly to the UI,
 * handling both full Incident objects and lightweight alert notifications.
 */
export function normalizeAlert(data) {
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
    camera_id: data.camera_id || (data.zone_id ? `CAM-${String(data.zone_id).replace(/\s+/g, '-').slice(0, 10).toUpperCase()}` : 'CAM-PRIMARY'),
    correlated_events,
    ...data, // Preserve any additional backend fields
    // Ensure our dynamic description and normalized sources override any legacy backend description
    description,
    sources: sourcesList,
  };
}

export function useAlertSocket(customUrl) {
  // Read WebSocket and API URLs from environment variables or defaults
  const wsUrl = customUrl || import.meta.env.VITE_WS_URL || DEFAULT_WS_URL;
  const apiUrl = import.meta.env.VITE_API_URL || DEFAULT_API_URL;

  // Real-time alert list in state (initialized with pre-loaded mock alerts so dashboard displays active threats on start)
  const [alerts, setAlerts] = useState(() => {
    return Array.isArray(INITIAL_ALERTS)
      ? INITIAL_ALERTS.map(normalizeAlert).filter(Boolean)
      : [];
  });

  // Connection state: 'connected' | 'reconnecting' | 'disconnected'
  const [connectionStatus, setConnectionStatus] = useState('reconnecting');

  // Stable references for WebSocket instance, reconnect timer, and dismissed alerts
  const socketRef = useRef(null);
  const reconnectTimerRef = useRef(null);
  const isMountedRef = useRef(true);
  const dismissedIdsRef = useRef(new Set());


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
      } catch (_e) {
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
            if (rawData.length === 0) {
              setAlerts([]);
              return;
            }
            const normalizedBatch = rawData
              .map(normalizeAlert)
              .filter(Boolean)
              .filter((a) => !dismissedIdsRef.current.has(a.incident_id));

            setAlerts((prevAlerts) => {
              // Add new alerts to the TOP, avoiding duplicate IDs
              const existingIds = new Set(prevAlerts.map(a => a.incident_id));
              const freshAlerts = normalizedBatch.filter(a => !existingIds.has(a.incident_id));
              return [...freshAlerts, ...prevAlerts];
            });
          } else if (rawData && typeof rawData === 'object') {
            const normalized = normalizeAlert(rawData);
            if (normalized) {
              // A new incoming alert should always be displayed even if old batch was cleared
              dismissedIdsRef.current.delete(normalized.incident_id);
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
        if (reconnectTimerRef.current) {
          clearTimeout(reconnectTimerRef.current);
        }
        reconnectTimerRef.current = setTimeout(() => {
          if (isMountedRef.current) {
            connect();
          }
        }, RECONNECT_DELAY_MS);
      };

      socket.onerror = (err) => {
        console.warn('[useAlertSocket] WebSocket error occurred:', err);
        if (isMountedRef.current) {
          setConnectionStatus('reconnecting');
        }
      };

    } catch (connectionError) {
      console.error('[useAlertSocket] Failed to create WebSocket instance:', connectionError);
      if (isMountedRef.current) {
        setConnectionStatus('reconnecting');
        if (reconnectTimerRef.current) {
          clearTimeout(reconnectTimerRef.current);
        }
        reconnectTimerRef.current = setTimeout(() => {
          if (isMountedRef.current) {
            connect();
          }
        }, RECONNECT_DELAY_MS);
      }
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

  // Fetch existing synthesized incidents from REST API on startup so dashboard restores data after page reload
  useEffect(() => {
    let isCancelled = false;
    const fetchExistingIncidents = async () => {
      try {
        const base = (apiUrl || DEFAULT_API_URL).replace(/\/+$/, '');
        const res = await fetch(`${base}/incidents`);
        if (res.ok) {
          const data = await res.json();
          if (Array.isArray(data) && data.length > 0 && !isCancelled) {
            const normalizedBatch = data
              .map(normalizeAlert)
              .filter(Boolean)
              .filter((a) => !dismissedIdsRef.current.has(a.incident_id));
            if (normalizedBatch.length > 0) {
              setAlerts((prevAlerts) => {
                const existingIds = new Set(prevAlerts.map((a) => a.incident_id));
                const freshAlerts = normalizedBatch.filter((a) => !existingIds.has(a.incident_id));
                return [...prevAlerts, ...freshAlerts];
              });
            }
          }
        }
      } catch (_err) {
        // Backend not reached or offline
      }
    };

    fetchExistingIncidents();
    return () => {
      isCancelled = true;
    };
  }, [apiUrl, normalizeAlert]);

  /**
   * Load mock demo alert scenarios for offline testing or demonstration
   */
  const loadMockAlerts = useCallback(() => {
    dismissedIdsRef.current.clear();
    const normalized = INITIAL_ALERTS.map(normalizeAlert).filter(Boolean);
    setAlerts(normalized);
  }, [normalizeAlert]);

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

  /**
   * Clear all active alerts from local feed and request backend purge
   */
  const clearAlerts = useCallback(async () => {
    setAlerts((currentAlerts) => {
      currentAlerts.forEach((a) => {
        if (a && a.incident_id) {
          dismissedIdsRef.current.add(a.incident_id);
        }
      });
      return [];
    });

    try {
      const apiUrl = import.meta.env.VITE_API_URL || 'http://localhost:8000';
      await fetch(`${apiUrl}/incidents`, { method: 'DELETE' });
    } catch {
      // Backend may not support DELETE /incidents yet
    }
  }, []);

  /**
   * Restore all previously dismissed alerts
   */
  const restoreAlerts = useCallback(() => {
    dismissedIdsRef.current.clear();
    connect();
  }, [connect]);

  return {
    alerts,
    setAlerts,
    clearAlerts,
    restoreAlerts,
    connectionStatus,
    statusText: connectionStatus === 'connected' ? 'LIVE' : 'RECONNECTING',
    isConnected: connectionStatus === 'connected',
    isReconnecting: connectionStatus === 'reconnecting',
    wsUrl,
    apiUrl,
    updateAlertStatus,
    loadMockAlerts,
  };
}

export default useAlertSocket;
