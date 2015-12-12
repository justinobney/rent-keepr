// Property Form
import React, {Component} from 'react';
import {reduxForm} from 'redux-form';
import classNames from 'classnames';
import {
  Button,
  Form,
  FormRow,
  FormInput,
  FormField,
  FormNote,
  FormIconField,
  Spinner
} from 'elemental';

let formConfig = {
    form: 'edit-property',
    fields: ['id', 'address1', 'address2', 'city', 'state', 'zipcode']
};

class PropertyForm extends Component {
  static propTypes = {
    apiError: React.PropTypes.object,
    fields: React.PropTypes.object,
    isSaving: React.PropTypes.any,
    handleSubmit: React.PropTypes.func,
  }
  render() {
    let {
      handleSubmit,
      isSaving,
      apiError,
      fields: {address1, address2, city, state, zipcode}
    } = this.props;

    let wrap = (propName, component) => {
      if(apiError && apiError.details.messages[propName]){
        return (
          <FormIconField iconPosition="right" iconKey="stop" iconColor="danger">
            {component}
        	</FormIconField>
        );
      } else {
        return component;
      }
    }

    return (
      <Form className="new-property-form" onSubmit={handleSubmit}>
        <FormField label="Address" className={classNames({'is-invalid': apiError && apiError.details.messages.address1})}>
          {wrap('address1', <FormInput placeholder="Address Line 1" name="address-street1" {...address1} />)}
        </FormField>
        <FormField className={classNames({'is-invalid': apiError && apiError.details.messages.address2})}>
          <FormInput placeholder="Address Line 2" name="address-street2" {...address2} />
        </FormField>
        <FormRow>
          <FormField width="two-thirds" className={classNames({'is-invalid': apiError && apiError.details.messages.city})}>
            {wrap('city', <FormInput placeholder="City" name="city" {...city} />)}
          </FormField>
          <FormField width="one-third" className={classNames({'is-invalid': apiError && apiError.details.messages.state})}>
            {wrap('state', <FormInput placeholder="State" name="state" {...state} />)}
          </FormField>
          <FormField width="one-third" className={classNames({'is-invalid': apiError && apiError.details.messages.zipcode})}>
            {wrap('zipcode', <FormInput width="one-third" placeholder="Post Code" name="zipcode" {...zipcode} />)}
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

export default reduxForm(formConfig,state => ({ // mapStateToProps
  initialValues: state.properties.data // will pull state into form's initialValues
}))(PropertyForm);
