import React from 'react';
import {render} from 'react-dom';
import RedBox from 'redbox-react';
import { ReduxRouter } from 'redux-router';
import { Provider } from 'react-redux'
import 'scss/base.scss';

import store from '@redux/create.js'
import routes from './routes';

import DevTools from '@redux/DevTools';

const root = document.querySelector("#mount");

try {
  render(
    <Provider store={store}>
      <div>
        <ReduxRouter>
          {routes}
        </ReduxRouter>
        <DevTools />
      </div>
    </Provider>,
    root);
} catch (e) {
  render(<RedBox error={e} />, root)
}
