// Login Screen
import React, {Component} from 'react';
import { connect } from 'react-redux';
import { pushState } from 'redux-router';
import { onLoginUserSuccess } from '@redux/modules/auth';
import './index.scss';

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
      <section className="login-wrapper">
        <header className="login-wrapper-header-header">
          <h1>Login</h1>
        </header>
        <main className="login-wrapper-header-content">
          <p>(just click the button)</p>
          <button onClick={::this._handleLogin}>Login</button>
        </main>
      </section>
    );
  }
};
