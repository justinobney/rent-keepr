// Property Form
import React, {Component} from 'react';
import {reduxForm} from 'redux-form';
import {
  Button,
  Form,
  FormRow,
  FormInput,
  FormField,
  FormNote,
  Spinner
} from 'elemental';

let formConfig = {
    form: 'new-property',
    fields: ['address1', 'address2', 'city', 'state', 'zipcode']
};

@reduxForm(formConfig)
export default class PropertyForm extends Component {
  static propTypes = {
    error: React.PropTypes.object,
    fields: React.PropTypes.object,
    isSaving: React.PropTypes.any,
    handleSubmit: React.PropTypes.func,
  }
  render() {
    let {
      handleSubmit,
      isSaving,
      error,
      fields: {address1, address2, city, state, zipcode}
    } = this.props;

    return (
      <Form className="new-property-form" onSubmit={handleSubmit}>
        <FormField label="Address" htmlFor="address-street1">
          <FormInput placeholder="Address Line 1" name="address-street1" {...address1} />
            {
              error && error.details.messages.address1 &&
              <FormNote type="danger">
                  {error && error.details.messages.address1}
              </FormNote>
            }
        </FormField>
        <FormField>
          <FormInput placeholder="Address Line 2" name="address-street2" {...address2} />
            {
              error && error.details.messages.address2 &&
              <FormNote type="danger">
                  {error && error.details.messages.address2}
              </FormNote>
            }
        </FormField>
        <FormRow>
          <FormField width="two-thirds">
            <FormInput placeholder="City" name="city" {...city} />
              {
                error && error.details.messages.city &&
                <FormNote type="danger">
                    {error && error.details.messages.city}
                </FormNote>
              }
          </FormField>
          <FormField width="one-third">
            <FormInput placeholder="State" name="state" {...state} />
              {
                error && error.details.messages.state &&
                <FormNote type="danger">
                    {error && error.details.messages.state}
                </FormNote>
              }
          </FormField>
          <FormField width="one-third">
            <FormInput width="one-third" placeholder="Post Code" name="zipcode" {...zipcode} />
              {
                error && error.details.messages.zipcode &&
                <FormNote type="danger">
                    {error && error.details.messages.zipcode}
                </FormNote>
              }
          </FormField>
        </FormRow>
        <Button type="primary" submit={true} disabled={isSaving}>
          Save Property
          {
            isSaving &&
            <span>&nbsp;&nbsp;<Spinner size="md" type="inverted" /></span>
          }
        </Button>
        <Button type="link-cancel" href="#/properties">
          Cancel
        </Button>
      </Form>
    );
  }
};
