// Property Detail Screen
import React, {Component} from 'react';
import { connect } from 'react-redux';
import { pushState } from 'redux-router';
import './index.scss';

import ContentPage from 'components/ContentPage';

let mapStateToProps = state => ({});
let mapDispatchToProps = dispatch => ({dispatch, pushState})

@connect(mapStateToProps, mapDispatchToProps)
export default class PropertyDetail extends Component {
  render() {
    return (
      <ContentPage className="property-detail-wrapper">
        <header className="content-page-header">
          <h1>Properties</h1>
        </header>
        <main>
          Property detail here...
        </main>
      </ContentPage>
    );
  }
};
