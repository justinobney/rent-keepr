// Login Screen
import React, {Component} from 'react';
import {pushState} from 'redux-router';
import {loginUser} from '@redux/modules/auth';
import {reduxForm} from 'redux-form';

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

let formConfig = {form: 'login', fields: ['email', 'password']};
let mapStateToProps = state => ({
  location: state.router.location,
  auth: state.auth
});
let mapDispatchToProps = dispatch => ({dispatch, pushState})

@reduxForm(formConfig, mapStateToProps, mapDispatchToProps)
export default class Login extends Component {
  _handleLogin(e){
		e.preventDefault();
		let {email, password} = this.props.fields;
		let credentials = {
	    'email':email.value,
	    'password':password.value
	  };
    this.props.dispatch(loginUser(credentials));
  }
  componentWillReceiveProps(nextProps) {
      if(nextProps.auth.isAuthenticated){
        this.props.dispatch(pushState(null, this.props.location.query.next))
      }
  }
  render() {
		let {auth, fields: {email, password}} = this.props;
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
									<FormInput autofocus type="email"
										placeholder="Enter email"
										name="basic-form-input-email"
										{...email} />
								</FormField>
								<FormField label="Password" htmlFor="basic-form-input-password">
									<FormInput type="password"
										placeholder="Password"
										name="basic-form-input-password"
										{...password} />
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
