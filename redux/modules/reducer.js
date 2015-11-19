import { combineReducers } from 'redux';
import test from './test';
import auth from './auth';
import { routerStateReducer } from 'redux-router';

export default combineReducers({
  router: routerStateReducer,
  test,
  auth
});
