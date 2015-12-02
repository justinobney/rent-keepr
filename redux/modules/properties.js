import { createReducer } from 'redux-create-reducer';
import api from 'root/api.js';

// actions
const GET_PROPERTIES_REQUEST = 'rent-keepr/properties/GET_PROPERTIES_REQUEST';
const GET_PROPERTIES_SUCCESS = 'rent-keepr/properties/GET_PROPERTIES_SUCCESS';
const GET_PROPERTIES_FAILURE = 'rent-keepr/properties/GET_PROPERTIES_FAILURE';

let initialState = {
  isFetching: false,
  items: []
};

// reducer
export default createReducer(initialState, {
  [GET_PROPERTIES_REQUEST](state, action) {
    let props = { isFetching: true };
    return {...state, ...props}
  },
  [GET_PROPERTIES_SUCCESS](state, action) {
    const { items } = action.payload;

    let props = {
      isFetching: false,
      items
    };

    return {...state, ...props}
  },
  [GET_PROPERTIES_FAILURE](state, action) {
    return { errorMessage: action.payload.message };
  },
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
