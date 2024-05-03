import React, { useState } from 'react';
import axios from 'axios';

function App() {
  const [domain, setDomain] = useState('');
  const [subdomains, setSubdomains] = useState([]);

  const getSubdomains = async () => {
    try {
      const response = await axios.post('http://localhost:5000/subdomains', { domain });
      setSubdomains(response.data); // Assuming the API returns an array of subdomains with their status
    } catch (error) {
      console.error('Failed to fetch subdomains:', error);
      setSubdomains([]); // Resetting subdomains on error to clear previous data
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
    </div>
  );
}

export default App;
