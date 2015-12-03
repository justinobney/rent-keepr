import { applyMiddleware, compose, createStore } from 'redux';
import reducer from './modules/reducer.js';
import createHistory from 'history/lib/createHashHistory'
import { reduxReactRouter } from 'redux-router';
import asyncMiddleware from 'redux-async';
import { persistState } from 'redux-devtools';
import routes from 'root/routes';
import DevTools from './DevTools';

const localStoragePersist = store => next => action => {
  if(action.meta && action.meta.saveLocal){
    let {type, key, test, transform} = action.meta.saveLocal;
    if(test(action)){
      let value = transform(action.payload);
      localStorage[`${type}Item`](key, value);
    }
  }

  return next(action);
}

let middleware = [ asyncMiddleware, localStoragePersist ];
let finalCreateStore;

if (process.env.NODE_ENV === 'production') {
  finalCreateStore = applyMiddleware(...middleware)(createStore)
} else {
  finalCreateStore = compose(
    applyMiddleware(...middleware),
    reduxReactRouter({routes, createHistory}),
    DevTools.instrument(),
    persistState(
      window.location.href.match(/[?&]debug_session=([^&]+)\b/)
    )
  )(createStore)
}

let store = finalCreateStore(reducer)

if (module.hot) {
  // Enable Webpack hot module replacement for reducers
  module.hot.accept('./modules/reducer', () => {
    const nextRootReducer = require('./modules/reducer');
    store.replaceReducer(nextRootReducer);
  });
}

export default store;
