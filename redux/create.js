import { applyMiddleware, compose, createStore } from 'redux';
import reducer from './modules/reducer.js';
import createHistory from 'history/lib/createHashHistory'
import { reduxReactRouter } from 'redux-router';
import asyncMiddleware from 'redux-async';
import { persistState } from 'redux-devtools';
import routes from 'root/routes';
import DevTools from './DevTools';

let combinedStore = compose(
  reduxReactRouter({
    routes,
    createHistory
  }),
  DevTools.instrument(),
  persistState(
    window.location.href.match(
      /[?&]debug_session=([^&]+)\b/
    )
  )
)(createStore);

export default applyMiddleware(asyncMiddleware)(combinedStore)(reducer);
