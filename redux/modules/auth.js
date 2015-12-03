import {pushState} from 'redux-router';
import {createReducer} from 'redux-create-reducer';
import api from 'root/api';

const actionBase = 'rent-keepr/auth';
const LOGIN_USER_REQUEST = `${actionBase}/LOGIN_USER_REQUEST`;
const LOGIN_USER_SUCCESS = `${actionBase}/LOGIN_USER_SUCCESS`;
const LOGIN_USER_FAILURE = `${actionBase}/LOGIN_USER_FAILURE`;
const VERIFY_TOKEN_SUCCESS = `${actionBase}/VERIFY_TOKEN_SUCCESS`;

const initialState = {
    token: null,
    user: null,
    isAuthenticated: false,
    isAuthenticating: false,
    statusText: null
};

export default createReducer(initialState, {
  [LOGIN_USER_REQUEST](state, action){
    let changes = {
      isAuthenticating: true,
      statusText: null
    };
    return {...state, ...changes};
  },

  [LOGIN_USER_SUCCESS](state, action){
    let {loginResponse, email} = action.payload;
    let changes = {
      isAuthenticating: false,
      isAuthenticated: true,
      statusText: null,
      user: {
        email,
        id: loginResponse.userId
      },
      token: loginResponse.id
    };
    return {...state, ...changes};
  },

  [LOGIN_USER_FAILURE](state, action) {
    let changes = {
      isAuthenticating: false,
      statusText: action.payload.message
    };
    return {...state, ...changes};
  },

  [VERIFY_TOKEN_SUCCESS](state, action){
    let {user, token} = action.payload;
    let changes = {
      isAuthenticating: false,
      isAuthenticated: true,
      user,
      token
    };
    return {...state, ...changes};
  }
});

export const loginUser = (email, password) => {
  let defaults = {
    'email':'justinobney@gmail.com',
    'password':'password'
  };
  return {
    types: [LOGIN_USER_REQUEST, LOGIN_USER_SUCCESS, LOGIN_USER_FAILURE],
    payload: {
      loginResponse: api.loginUser(defaults),
      email
    }
  }
}

export const verifyToken = ({id, token}) => {
  return {
    types: [LOGIN_USER_REQUEST, VERIFY_TOKEN_SUCCESS, LOGIN_USER_FAILURE],
    payload: {
      user: api.verifyToken(id, token),
      token
    }
  }
}
