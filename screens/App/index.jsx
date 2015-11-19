// App Component
import React, {Component} from 'react';
import { Link } from 'react-router'
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
            <Link to="/" className="app-logo">
              Rent-Keepr
            </Link>
          </h1>
        </section>
        <main className="app-main">
          {this.props.children}
        </main>
      </div>
    );
  }
};
