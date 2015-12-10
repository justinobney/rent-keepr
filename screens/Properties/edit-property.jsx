// Edit Property Screen
import React, {Component} from 'react';
import {connect} from 'react-redux';
import {pushState} from 'redux-router';
import {setProperty, updateProperty} from '@redux/modules/properties'

import './index.scss';

import ContentPage from 'components/ContentPage';
import PropertyForm from 'components/Properties/property-form';

let mapStateToProps = state => ({
  properties: state.properties,
  router: state.router
});
let mapDispatchToProps = dispatch => ({dispatch, pushState})

class EditProperty extends Component {
  _handleSubmit(data){
    this.props.dispatch(updateProperty(data));
  }
  componentWillMount(){
    let {properties, router} = this.props;
    let property = properties.items.find(item => item.id == router.params.propertyId);
    this.props.dispatch(setProperty(property));
  }
  componentWillReceiveProps(nextProps) {
    let {properties: {error, saveSuccess}} = nextProps;
    if(saveSuccess && !error){
      this.props.dispatch(pushState(null, '/properties'))
    }
  }
  render() {
    let {properties: {error, isSaving}, router} = this.props;
    return (
      <div className="new-property-wrapper">
        <ContentPage className="m-single">
          <header className="content-page-header">
            <h1>Edit Property</h1>
          </header>
          <main>
            <PropertyForm onSubmit={::this._handleSubmit}
              isSaving={isSaving}
              apiError={error} />
          </main>
        </ContentPage>
      </div>
    );
  }
};

export default connect(mapStateToProps, mapDispatchToProps)(EditProperty);
