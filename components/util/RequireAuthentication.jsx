import React from 'react';
import { connect } from 'react-redux';
import { pushState } from 'redux-router';
import Wrapper from './Wrapper';

const mapStateToProps = (state) => ({
  token: state.auth.token,
  userName: state.auth.userName,
  isAuthenticated: state.auth.isAuthenticated
});

export function requireAuthentication(Component) {
  class AuthenticatedComponent extends React.Component {
    componentWillMount () {
      this.checkAuth();
    }
    componentWillReceiveProps (nextProps) {
      this.checkAuth();
    }
    checkAuth () {
      if (!this.props.isAuthenticated) {
        let redirectAfterLogin = this.props.location.pathname;
        this.props.dispatch(pushState(null, `/login?next=${redirectAfterLogin}`));
      }
    }
    render () {
      return (
        <Wrapper>
          {this.props.isAuthenticated === true
            ? <Component {...this.props}/>
            : null }
        </Wrapper>
      );
    }
  }

  return connect(mapStateToProps)(AuthenticatedComponent);
}
