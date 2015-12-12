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

const UPDATE_PROPERTY_REQUEST = `${actionBase}/UPDATE_PROPERTY_REQUEST`;
const UPDATE_PROPERTY_SUCCESS = `${actionBase}/UPDATE_PROPERTY_SUCCESS`;
const UPDATE_PROPERTY_FAILURE = `${actionBase}/UPDATE_PROPERTY_FAILURE`;

const RESET_PROPERTY = `${actionBase}/RESET_PROPERTY`;
const SET_PROPERTY = `${actionBase}/RESET_PROPERTY`;

let initialState = {
  isFetching: false,
  isSaving: false,
  items: [],
  data: {}
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
      items: items.map((item, idx) => ({...item, tenant:'bob', rent:500.00, current:idx%3!==1}))
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
    let changes = {
      isSaving: false,
      saveSuccess: true,
      error: null
    };
    return {...state, ...changes}
  },

  [CREATE_PROPERTY_FAILURE](state, action) {
    let {error} = action.payload;
    let changes = {
      isSaving: false,
      saveSuccess: false,
      error
    };
    return {...state, ...changes}
  },

  [UPDATE_PROPERTY_REQUEST](state, action) {
    let changes = {
      isSaving: true
    };
    return {...state, ...changes}
  },

  [UPDATE_PROPERTY_SUCCESS](state, action) {
    const { property } = action.payload;
    let changes = {
      isSaving: false,
      saveSuccess: true,
      error: null
    };
    return {...state, ...changes}
  },

  [UPDATE_PROPERTY_FAILURE](state, action) {
    let {error} = action.payload;
    let changes = {
      isSaving: false,
      saveSuccess: false,
      error
    };
    return {...state, ...changes}
  },

  [RESET_PROPERTY](state, action){
    let changes = {
      isSaving: false,
      saveSuccess: false,
      error: null,
      data: {}
    };
    return {...state, ...changes}
  },

  [SET_PROPERTY](state, action){
    let changes = {
      isSaving: false,
      saveSuccess: false,
      data: action.payload,
      error: null
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

export const updateProperty = (property) => {
  return {
    types: [UPDATE_PROPERTY_REQUEST, UPDATE_PROPERTY_SUCCESS, UPDATE_PROPERTY_FAILURE],
    payload: {
      property: api.updateProperty(property)
    }
  }
}

export const resetProperty = () => {
  return {
    type: RESET_PROPERTY
  }
}

export const setProperty = (data) => {
  return {
    type: SET_PROPERTY,
    payload: data
  }
}
