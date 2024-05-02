import React, { useState, useEffect } from 'react';
import axios from 'axios';
import io from 'socket.io-client';

function App() {
  const [domain, setDomain] = useState('');
  const [foundSubdomains, setFoundSubdomains] = useState([]);
  const [validatedSubdomains, setValidatedSubdomains] = useState([]);

  useEffect(() => {
    const socket = io('http://localhost:5000');
    socket.on('subdomain_found', (data) => {
      setFoundSubdomains(prevSubdomains => [...prevSubdomains, data.subdomain]);
    });
    socket.on('subdomain_validated', (data) => {
      setValidatedSubdomains(prevSubdomains => [...prevSubdomains, data]);
    });
  }, []);

  const getSubdomains = async () => {
    await axios.post('http://localhost:5000/subdomains', { domain });
  };

  return (
    <div>
      <input type="text" value={domain} onChange={e => setDomain(e.target.value)} />
      <button onClick={getSubdomains}>Get Subdomains</button>
      <h2>Found Subdomains</h2>
      <ul>
        {foundSubdomains.map((subdomain, index) => (
          <li key={index}>{subdomain}</li>
        ))}
      </ul>
      <h2>Validated Subdomains</h2>
      <ul>
        {validatedSubdomains.map((subdomain, index) => (
          <li key={index}>{subdomain.subdomain}</li>
        ))}
      </ul>
    </div>
  );
}

export default App;
