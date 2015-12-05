import { createReducer } from 'redux-create-reducer';
import api from 'root/api.js';

// actions
const actionBase = 'rent-keepr/properties';

const GET_PROPERTIES_REQUEST = `${actionBase}/GET_PROPERTIES_REQUEST`;
const GET_PROPERTIES_SUCCESS = `${actionBase}/GET_PROPERTIES_SUCCESS`;
const GET_PROPERTIES_FAILURE = `${actionBase}/GET_PROPERTIES_FAILURE`;

const CREATE_PROPERTY_REQUEST = `${actionBase}/CREATE_PROPERTY_REQUEST`;
const CREATE_PROPERTY_SUCCESS = `${actionBase}/CREATE_PROPERTY_SUCCESS`;
const CREATE_PROPERTY_FAILURE = `${actionBase}/CREATE_PROPERTY_FAILURE`;

let initialState = {
  isFetching: false,
  isSaving: false,
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
  },
  [CREATE_PROPERTY_REQUEST](state, action) {
    let changes = {
      isSaving: true
    };
    return {...state, ...changes}
  },
  [CREATE_PROPERTY_SUCCESS](state, action) {
    const { property } = action.payload;
    let changes = {
      isSaving: false,
      items: [...state.items, property],
      error: null
    };
    return {...state, ...changes}
  },
  [CREATE_PROPERTY_FAILURE](state, action) {
    let {error} = action.payload;
    let changes = {
      isSaving: false,
      error
    };
    return {...state, ...changes}
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

export const createProperty = (property) => {
  return {
    types: [CREATE_PROPERTY_REQUEST, CREATE_PROPERTY_SUCCESS, CREATE_PROPERTY_FAILURE],
    payload: {
      property: api.createProperty(property)
    }
  }
}
