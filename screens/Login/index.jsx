// Login Screen
import React, {Component} from 'react';
import { connect } from 'react-redux';
import { pushState } from 'redux-router';
import { loginUser } from '@redux/modules/auth';
import './index.scss';
import {
	Alert,
	Button,
	Form,
	FormField,
	FormInput,
	FormRow,
	Glyph,
	Spinner
} from'elemental';

import ContentPage from 'components/ContentPage';

let mapStateToProps = state => ({
  location: state.router.location,
  auth: state.auth
});
let mapDispatchToProps = dispatch => ({dispatch, pushState})

@connect(mapStateToProps, mapDispatchToProps)
export default class Login extends Component {
  _handleLogin(e){
		e.preventDefault();
		let defaults = {
	    'email':'justinobney@gmail.com',
	    'password':'password'
	  };
    this.props.dispatch(loginUser(defaults));
  }
  componentWillReceiveProps(nextProps) {
      if(nextProps.auth.isAuthenticated){
        this.props.dispatch(pushState(null, this.props.location.query.next))
      }
  }
  render() {
		let {auth} = this.props;
		let loading = <span>&nbsp;&nbsp;<Spinner size="md" type="inverted" /></span>;
		let icon = <Glyph icon="lock" />;
		let buttonIcon = auth.isAuthenticating ? loading : icon;
    return (
			<div className="login-wrapper">
				<ContentPage className="m-single">
	        <header className="content-page-header">
	          <h1>Login</h1>
	        </header>
	        <main>
						{
							this.props.auth.statusText &&
							<Alert type="danger"><strong>Error:</strong> {this.props.auth.statusText}</Alert>
						}
	          <Form className="login-form" onSubmit={::this._handleLogin}>
								<FormField label="Email address" htmlFor="basic-form-input-email">
									<FormInput autofocus type="email" placeholder="Enter email" name="basic-form-input-email" />
								</FormField>
								<FormField label="Password" htmlFor="basic-form-input-password">
									<FormInput type="password" placeholder="Password" name="basic-form-input-password" />
								</FormField>
								<Button type="primary" submit={true} disabled={auth.isAuthenticating}>
									Log In {buttonIcon}
								</Button>
							</Form>
	        </main>
	      </ContentPage>
			</div>
    );
  }
};
