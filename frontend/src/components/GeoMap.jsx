import React, { useState, useEffect } from 'react';
import { MapContainer, TileLayer, Marker, Popup, CircleMarker } from 'react-leaflet';
import { dashboardAPI } from '../services/api';
import 'leaflet/dist/leaflet.css';

/**
 * Geographic Map Component
 * Shows attack distribution on world map
 */
const GeoMap = () => {
  const [locations, setLocations] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchLocations = async () => {
      try {
        const response = await dashboardAPI.getGeographic();
        setLocations(response.data.locations);
        setLoading(false);
      } catch (error) {
        console.error('Failed to fetch geographic data:', error);
        setLoading(false);
      }
    };

    fetchLocations();
    const interval = setInterval(fetchLocations, 60000); // Refresh every minute
    return () => clearInterval(interval);
  }, []);

  if (loading) {
    return <div className="flex items-center justify-center h-96">Loading map...</div>;
  }

  return (
    <div className="bg-gray-800 rounded-lg p-6">
      <h2 className="text-xl font-semibold mb-4">Attack Source Geographic Distribution</h2>
      <MapContainer
        center={[20, 0]}
        zoom={2}
        style={{ height: '500px', width: '100%', borderRadius: '8px' }}
      >
        <TileLayer
          url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
          attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>'
        />
        {locations.map((loc, index) => {
          // Color based on threat score
          const color =
            loc.avg_threat_score >= 76 ? 'red' :
            loc.avg_threat_score >= 51 ? 'orange' :
            loc.avg_threat_score >= 26 ? 'yellow' : 'green';

          // Size based on attack count
          const radius = Math.min(Math.log(loc.attack_count) * 3, 30);

          return (
            <CircleMarker
              key={index}
              center={[loc.latitude, loc.longitude]}
              radius={radius}
              fillColor={color}
              color={color}
              weight={1}
              opacity={0.8}
              fillOpacity={0.6}
            >
              <Popup>
                <div className="text-gray-900">
                  <h3 className="font-bold">{loc.country}</h3>
                  <p>Attacks: {loc.attack_count}</p>
                  <p>Avg Threat Score: {loc.avg_threat_score}</p>
                </div>
              </Popup>
            </CircleMarker>
          );
        })}
      </MapContainer>
      
      {/* Legend */}
      <div className="mt-4 flex gap-4 text-sm">
        <div className="flex items-center gap-2">
          <div className="w-4 h-4 rounded-full bg-red-600"></div>
          <span>Critical (76-100)</span>
        </div>
        <div className="flex items-center gap-2">
          <div className="w-4 h-4 rounded-full bg-orange-600"></div>
          <span>High (51-75)</span>
        </div>
        <div className="flex items-center gap-2">
          <div className="w-4 h-4 rounded-full bg-yellow-600"></div>
          <span>Medium (26-50)</span>
        </div>
        <div className="flex items-center gap-2">
          <div className="w-4 h-4 rounded-full bg-green-600"></div>
          <span>Low (0-25)</span>
        </div>
      </div>
    </div>
  );
};

export default GeoMap;
