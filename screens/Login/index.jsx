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
	Glyph
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
    this.props.dispatch(loginUser());
  }
  componentWillReceiveProps(nextProps) {
      if(nextProps.auth.isAuthenticated){
        this.props.dispatch(pushState(null, this.props.location.query.next))
      }
  }
  render() {
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
								<Button type="primary" submit={true}>
									Log In <Glyph icon="lock" />
								</Button>
							</Form>
	        </main>
	      </ContentPage>
			</div>
    );
  }
};
