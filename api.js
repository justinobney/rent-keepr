let base = 'http://localhost:3000';

let jsonHeaders = {
  'Accept': 'application/json',
  'Content-Type': 'application/json'
};

let post = (url, data, opts) => {
  let default_opts = {
    method: 'post',
    headers: {...jsonHeaders},
    body: JSON.stringify(data)
  };

  opts = {...default_opts, ...opts};

  return asyncFetch(`${base}${url}`, opts)
}

function checkStatus(response) {
  if (response.status < 200 || response.status >= 300) {
    var error = new Error(response.statusText)
    error.response = response
    throw error
  }
}

async function asyncFetch(url, opts = {}) {
  var response = await fetch(url, opts);
  checkStatus(response);
  return await response.json();
}

export default {
  getProperties: async () => asyncFetch(`${base}/api/properties`),
  createProperty: async ({address1, address2, city, state, zipcode}) => {
    return post('/api/properties', {address1, address2, city, state, zipcode});
  },
  loginUser: async ({email, password}) => {
    return post('/api/Users/login', {email, password});
  },
  verifyToken: async (userId, token) => asyncFetch(`${base}/api/Users/${userId}?access_token=${token}`),
}
