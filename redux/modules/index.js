import { combineReducers } from 'redux';
import properties from './properties';
import auth from './auth';
import { routerStateReducer } from 'redux-router';
import {reducer as formReducer} from 'redux-form';

export default combineReducers({
  router: routerStateReducer,
  form: formReducer,
  properties,
  auth,
  auth2:auth
});
