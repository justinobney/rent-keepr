import { createReducer } from 'redux-create-reducer';
import api from 'root/api.js';

// actions
const actionBase = 'rent-keepr/properties';
const GET_PROPERTIES_REQUEST = `${actionBase}/GET_PROPERTIES_REQUEST`;
const GET_PROPERTIES_SUCCESS = `${actionBase}/GET_PROPERTIES_SUCCESS`;
const GET_PROPERTIES_FAILURE = `${actionBase}/GET_PROPERTIES_FAILURE`;

let initialState = {
  isFetching: false,
  items: []
};

// reducer
export default createReducer(initialState, {
  [GET_PROPERTIES_REQUEST](state, action) {
    let changes = { isFetching: true };
    delete state.errorMessage;
    return {...state, ...changes}
  },
  [GET_PROPERTIES_SUCCESS](state, action) {
    const { items } = action.payload;

    let changes = {
      isFetching: false,
      items
    };
    delete state.errorMessage;
    return {...state, ...changes}
  },
  [GET_PROPERTIES_FAILURE](state, action) {
    return { errorMessage: action.payload.message };
  }
});

// action creators
export const getProperties = () => {
  return {
    types: [GET_PROPERTIES_REQUEST, GET_PROPERTIES_SUCCESS, GET_PROPERTIES_FAILURE],
    payload: {
      items: api.getProperties()
    }
  }
}
