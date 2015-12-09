let base = 'http://localhost:3000';
let jsonHeaders = {
  'Accept': 'application/json',
  'Content-Type': 'application/json'
};

export default {
  getProperties: async () => asyncFetch(`${base}/api/properties`),
  createProperty: async ({address1, address2, city, state, zipcode}) => {
    return send('/api/properties', {address1, address2, city, state, zipcode});
  },
  updateProperty: async ({id, address1, address2, city, state, zipcode}) => {
    let opts = {method: 'put'}
    let data = {address1, address2, city, state, zipcode};
    return send(`/api/properties/${id}`, data, opts);
  },
  loginUser: async ({email, password}) => {
    return send('/api/Users/login', {email, password});
  },
  verifyToken: async (userId, token) => asyncFetch(`${base}/api/Users/${userId}?access_token=${token}`),
}

async function asyncFetch(url, opts = {}) {
  let response = await fetch(url, opts);
  let json = await response.json();
  checkStatus(response, json);
  return json;
}

function checkStatus(response, json) {
  if (response.status < 200 || response.status >= 300) {
    let error = new Error(response.statusText)
    error.response = response
    Object.assign(error, json);
    throw error
  }
}

function send(url, data, opts) {
  let default_opts = {
    method: 'post',
    headers: {...jsonHeaders},
    body: JSON.stringify(data)
  };

  opts = {...default_opts, ...opts};
  return asyncFetch(`${base}${url}`, opts)
}
