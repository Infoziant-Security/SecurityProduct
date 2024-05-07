import React, { useState } from 'react';
import axios from 'axios';

function App() {
  const [domain, setDomain] = useState('');
  const [subdomains, setSubdomains] = useState([]);
  const [waybackUrls, setWaybackUrls] = useState({});

  const getSubdomains = async () => {
    try {
      const response = await axios.post('http://localhost:5000/api/subdomains', { domain });
      setSubdomains(response.data.validated_subdomains);
      setWaybackUrls(response.data.wayback_urls);
    } catch (error) {
      console.error('Failed to fetch subdomains:', error);
      setSubdomains([]); // Resetting subdomains on error to clear previous data
      setWaybackUrls({});
    }
  };

  return (
    <div>
      <input 
        type="text" 
        value={domain} 
        onChange={e => setDomain(e.target.value)} 
        placeholder="Enter domain to find subdomains"
      />
      <button onClick={getSubdomains}>Find Subdomains</button>
      <h2>Subdomains</h2>
      {subdomains.length > 0 ? (
        <ul>
          {subdomains.map((subdomain, index) => (
            <li key={index}>
              {subdomain.subdomain} - Status: {subdomain.status_code}
            </li>
          ))}
        </ul>
      ) : (
        <p>No subdomains found or error in fetching subdomains.</p>
      )}
      <h2>Wayback URLs</h2>
      {Object.keys(waybackUrls).length > 0 ? (
        Object.entries(waybackUrls).map(([key, urls], index) => (
          <div key={index}>
            <h3>{key}</h3>
            <ul>
              {urls.map((url, idx) => <li key={idx}>{url}</li>)}
            </ul>
          </div>
        ))
      ) : (
        <p>No Wayback URLs found or error in fetching URLs.</p>
      )}
    </div>
  );
}

export default App;
