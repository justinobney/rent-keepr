// New Property Screen
import React, {Component} from 'react';
import {connect} from 'react-redux';
import {pushState} from 'redux-router';
import {resetProperty, createProperty} from '@redux/modules/properties'

import './index.scss';

import ContentPage from 'components/ContentPage';
import PropertyForm from 'components/Properties/property-form';

let mapStateToProps = state => ({properties: state.properties});
let mapDispatchToProps = dispatch => ({dispatch, pushState})


class NewProperty extends Component {
  _handleSubmit(data){
    this.props.dispatch(createProperty(data));
  }
  componentWillMount(){
    this.props.dispatch(resetProperty());
  }
  componentWillReceiveProps(nextProps) {
    let {properties: {error, saveSuccess}} = nextProps;
    if(saveSuccess && !error){
      this.props.dispatch(pushState(null, '/properties'))
    }
  }
  render() {
    let {properties: {error, isSaving}} = this.props;
    return (
      <div className="new-property-wrapper">
        <ContentPage className="m-single">
          <header className="content-page-header">
            <h1>New Property</h1>
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

export default connect(mapStateToProps, mapDispatchToProps)(NewProperty)
