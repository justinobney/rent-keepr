import {pushState} from 'redux-router';

const actionBase = 'rent-keepr/auth';
const LOGIN_USER_REQUEST = `${actionBase}/LOGIN_USER_REQUEST`;
const LOGIN_USER_SUCCESS = `${actionBase}/LOGIN_USER_SUCCESS`;

const initialState = {
    token: null,
    userName: null,
    isAuthenticated: false,
    isAuthenticating: false,
    statusText: null
};

export default function reducer(state = initialState, action = {}) {
  let changes = {};
  switch (action.type) {
    case LOGIN_USER_REQUEST:
      changes = {
        isAuthenticating: true,
        statusText: null
      };
      return {...state, ...changes}
    case LOGIN_USER_SUCCESS:
      changes = {
        isAuthenticating: false,
        isAuthenticated: true,
      };
      return {...state, ...changes}
    default: return state;
  }
}

export function onLoginUserSuccess() {
  return { type: LOGIN_USER_SUCCESS };
}
