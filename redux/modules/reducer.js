import { combineReducers } from 'redux';
import properties from './properties';
import auth from './auth';
import { routerStateReducer } from 'redux-router';

export default combineReducers({
  router: routerStateReducer,
  properties,
  auth
});
