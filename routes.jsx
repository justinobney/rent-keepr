import React from 'react';
import { Route, IndexRoute } from 'react-router'
import {requireAuthentication} from 'components/util/RequireAuthentication';

import Wrapper from 'components/util/Wrapper'

import App from './screens/App/';
import About from './screens/About/';
import Home from './screens/Home/';
import Login from './screens/Login/';
import PropertyList from './screens/Properties/';
import NewProperty from './screens/Properties/new-property.jsx';
import EditProperty from './screens/Properties/edit-property.jsx';

let routes = (
  <Route path="/" component={App}>
    <Route component={requireAuthentication(Wrapper)}>
      <IndexRoute component={Home}/>
      <Route path="properties">
        <IndexRoute component={PropertyList}/>
        <Route path="new" component={NewProperty} />
        <Route path=":propertyId" component={EditProperty} />
      </Route>
    </Route>
    <Route path="login" component={Login} />
  </Route>
);

export default routes
