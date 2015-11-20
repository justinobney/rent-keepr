// App Component
import React, {Component} from 'react';
import { IndexLink, Link } from 'react-router'
import { connect } from 'react-redux';
import { pushState } from 'redux-router';
import Wrapper from 'components/util/Wrapper';

import './index.scss';

let mapStateToProps = state => ({ location: state.router.location });
let mapDispatchToProps = dispatch => ({dispatch, pushState})

@connect(mapStateToProps, mapDispatchToProps)
export default class App extends Component {
  render() {
    return (
      <div className="app-wrapper">
        <header className="app-top-bar">
        </header>
        <section className="app-side-bar">
          <h1>
            <IndexLink to="/" className="app-logo">
              Rent-Keepr
            </IndexLink>
          </h1>
          <nav className="app-side-bar-nav">
            <IndexLink to="/" className="app-side-bar-nav-link" activeClassName="is-active">
              Dashboard
            </IndexLink>
            <Link to="/properties" className="app-side-bar-nav-link" activeClassName="is-active">
              Properties
            </Link>
            <Link to="/tenants" className="app-side-bar-nav-link" activeClassName="is-active">
              Tenants
            </Link>
            <Link to="/reports" className="app-side-bar-nav-link" activeClassName="is-active">
              Reports
            </Link>
          </nav>
        </section>
        <main className="app-main">
          {this.props.children}
        </main>
      </div>
    );
  }
};
