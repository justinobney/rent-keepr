import { compose, createStore } from 'redux';
import reducer from './modules/reducer.js';
import createHistory from 'history/lib/createHashHistory'
import { reduxReactRouter } from 'redux-router';
import { persistState } from 'redux-devtools';
import routes from 'root/routes';
import DevTools from './DevTools';

export default compose(
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
)(createStore)(reducer);
