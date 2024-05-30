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
      
    </div>
  );
}

export default App;
