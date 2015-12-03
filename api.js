let base = 'http://localhost:3000';

let jsonHeaders = {
  'Accept': 'application/json',
  'Content-Type': 'application/json'
};

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
  loginUser: async ({email, password}) => {
    let opts = {
      method: 'post',
      headers: {...jsonHeaders},
      body: JSON.stringify({email, password})
    };
    return asyncFetch(`${base}/api/Users/login`, opts)
  },
  verifyToken: async (userId, token) => asyncFetch(`${base}/api/Users/${userId}?access_token=${token}`),
}
