// Login Screen
import React, {Component} from 'react';
import { connect } from 'react-redux';
import { pushState } from 'redux-router';
import { onLoginUserSuccess } from '@redux/modules/auth';
import './index.scss';

import ContentPage from 'components/ContentPage';

let mapStateToProps = state => ({
  location: state.router.location,
  auth: state.auth
});
let mapDispatchToProps = dispatch => ({dispatch, pushState})

@connect(mapStateToProps, mapDispatchToProps)
export default class Login extends Component {
  _handleLogin(){
    this.props.dispatch(onLoginUserSuccess());
  }
  componentWillReceiveProps(nextProps) {
      if(nextProps.auth.isAuthenticated){
        this.props.dispatch(pushState(null, this.props.location.query.next))
      }
  }
  render() {
    return (
      <ContentPage className="login-wrapper">
        <header className="">
          <h1>Login</h1>
        </header>
        <main className="">
          <p>(just click the button)</p>
          <button onClick={::this._handleLogin}>Login</button>
        </main>
      </ContentPage>
    );
  }
};
