import React, { useEffect, useState } from 'react';
import axios from 'axios';

const SubdomainList = () => {
  const [subdomains, setSubdomains] = useState([]);
  const [domain, setDomain] = useState('');

  const handleSubmit = (event) => {
    event.preventDefault();
    const eventSource = new EventSource(`http://localhost:5000/subdomains?domain=${domain}`);

    eventSource.onmessage = (event) => {
      setSubdomains((subdomains) => [...subdomains, JSON.parse(event.data)]);
    };
};



  return (
    <div>
      <form onSubmit={handleSubmit}>
        <label>
          Domain:
          <input type="text" value={domain} onChange={e => setDomain(e.target.value)} />
        </label>
        <input type="submit" value="Submit" />
      </form>
      {subdomains.map((subdomain, index) => (
        <p key={index}>{subdomain.subdomain}</p>
      ))}
    </div>
  );
};

export default SubdomainList;
