let base = 'http://localhost:3000';

async function asyncFetch(url) {
  var response = await fetch(url);
  return await response.json();
}

export default {
  getProperties: async () => asyncFetch(`${base}/api/properties`)
}
