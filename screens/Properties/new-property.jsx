// New Property Screen
import React, { Component } from 'react';
import { connect } from 'react-redux';
import { pushState } from 'redux-router';
import {
  Button,
  Form,
  FormRow,
  FormInput,
  FormField,
  FormSelect
} from 'elemental';

// import './index.scss';

import ContentPage from 'components/ContentPage';

let mapStateToProps = state => ({});
let mapDispatchToProps = dispatch => ({dispatch, pushState})

@connect(mapStateToProps, mapDispatchToProps)
export default class NewProperty extends Component {
  render() {
    return (
      <ContentPage className="new-property-wrapper">
        <header className="content-page-header">
          <h1>New Property</h1>
        </header>
        <main>
          <Form className="new-property-form">
            <FormField label="Address" htmlFor="address-street1">
            	<FormInput placeholder="Address Line 1" name="address-street1" />
            </FormField>
            <FormField>
            	<FormInput placeholder="Address Line 2" name="address-street2" />
            </FormField>
            <FormRow>
            	<FormField width="two-thirds">
            		<FormInput placeholder="City" name="city" />
            	</FormField>
            	<FormField width="one-third">
            		<FormInput placeholder="State" name="state" />
            	</FormField>
            	<FormField width="one-third">
            		<FormInput width="one-third" placeholder="Post Code" name="city" />
            	</FormField>
            	<FormField width="two-thirds">
            		<FormSelect options={['']} firstOption="Country" onChange={() => {}} />
            	</FormField>
            </FormRow>
            <Button type="primary">Save Property</Button>
            <Button type="link-cancel">Cancel</Button>
          </Form>
        </main>
      </ContentPage>
    );
  }
};
