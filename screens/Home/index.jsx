// Home Screen
import React, {Component} from 'react';
import { Link } from 'react-router'
import { connect } from 'react-redux';
import { pushState } from 'redux-router';
import './index.scss';

import ContentPage from 'components/ContentPage';

let mapStateToProps = state => ({});
let mapDispatchToProps = dispatch => ({dispatch, pushState})

@connect(mapStateToProps, mapDispatchToProps)
export default class Home extends Component {
  render() {
    return (
      <div className="home-wrapper">
        <ContentPage>
          <header className="content-page-header">
            <h1>Dashboard</h1>
          </header>
          <main>
            <p>Dashboardy things and such</p>
          </main>
        </ContentPage>
      </div>
    );
  }
};
