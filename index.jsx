import React from 'react';
import {render} from 'react-dom';
import RedBox from 'redbox-react';
import { ReduxRouter } from 'redux-router';
import { Provider } from 'react-redux'

import store from '@redux/create.js'
import {verifyToken} from '@redux/modules/auth'
import routes from './routes';

import DevTools from '@redux/DevTools';

import 'scss/elemental.less';
import 'scss/base.scss';

const root = document.querySelector("#mount");

let authInfo = localStorage.getItem('authInfo');
if (authInfo) {
  authInfo = JSON.parse(authInfo)
  store.dispatch(verifyToken(authInfo))
}

try {
  render(
    <Provider store={store}>
      <div>
        <ReduxRouter>
          {routes}
        </ReduxRouter>
        {__DEVTOOLS__ && <DevTools />}
      </div>
    </Provider>,
    root);
} catch (e) {
  render(<RedBox error={e} />, root)
}
