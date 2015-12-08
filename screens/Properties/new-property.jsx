// New Property Screen
import React, {Component} from 'react';
import {reduxForm} from 'redux-form';
import {pushState} from 'redux-router';
import {createProperty} from '@redux/modules/properties'
import {
  Alert,
  Button,
  Form,
  FormRow,
  FormInput,
  FormField,
  FormNote,
  Spinner
} from 'elemental';

import './index.scss';

import ContentPage from 'components/ContentPage';

let formConfig = {
    form: 'new-property',
    fields: ['address1', 'address2', 'city', 'state', 'zipcode']
};
let mapStateToProps = state => ({properties: state.properties});
let mapDispatchToProps = dispatch => ({dispatch, pushState})

@reduxForm(formConfig, mapStateToProps, mapDispatchToProps)
export default class NewProperty extends Component {
  _handleSubmit(data){
    this.props.dispatch(createProperty(data));
  }
  componentWillReceiveProps(nextProps) {
    let wasSaving = this.props.properties.isSaving;
    let {properties: {error, isSaving}} = nextProps;
    if(wasSaving && !isSaving && !error){
      this.props.dispatch(pushState(null, '/properties'))
    }
  }
  render() {
    let {
      properties,
      handleSubmit,
      fields: {address1, address2, city, state, zipcode}
    } = this.props;
    return (
      <div className="new-property-wrapper">
        <ContentPage className="m-single">
          <header className="content-page-header">
            <h1>New Property</h1>
          </header>
          <main>
            <Form className="new-property-form" onSubmit={handleSubmit(::this._handleSubmit)}>
              <FormField label="Address" htmlFor="address-street1">
              	<FormInput placeholder="Address Line 1" name="address-street1" {...address1} />
                  {
                    properties.error && properties.error.details.messages.address1 &&
                    <FormNote type="danger">{properties.error && properties.error.details.messages.address1}</FormNote>
                  }
              </FormField>
              <FormField>
              	<FormInput placeholder="Address Line 2" name="address-street2" {...address2} />
                  {
                    properties.error && properties.error.details.messages.address2 &&
                    <FormNote type="danger">{properties.error && properties.error.details.messages.address2}</FormNote>
                  }
              </FormField>
              <FormRow>
              	<FormField width="two-thirds">
              		<FormInput placeholder="City" name="city" {...city} />
                    {
                      properties.error && properties.error.details.messages.city &&
                      <FormNote type="danger">{properties.error && properties.error.details.messages.city}</FormNote>
                    }
              	</FormField>
              	<FormField width="one-third">
              		<FormInput placeholder="State" name="state" {...state} />
                    {
                      properties.error && properties.error.details.messages.state &&
                      <FormNote type="danger">{properties.error && properties.error.details.messages.state}</FormNote>
                    }
              	</FormField>
              	<FormField width="one-third">
              		<FormInput width="one-third" placeholder="Post Code" name="zipcode" {...zipcode} />
                    {
                      properties.error && properties.error.details.messages.zipcode &&
                      <FormNote type="danger">{properties.error && properties.error.details.messages.zipcode}</FormNote>
                    }
              	</FormField>
              </FormRow>
              <Button type="primary" submit={true} disabled={properties.isSaving}>
                Save Property
                {
                  properties.isSaving &&
                  <span>&nbsp;&nbsp;<Spinner size="md" type="inverted" /></span>
                }
              </Button>
              <Button type="link-cancel" href="#/properties">
                Cancel
              </Button>
            </Form>
          </main>
        </ContentPage>
      </div>
    );
  }
};
