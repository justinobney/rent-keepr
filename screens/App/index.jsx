// App Component
import React, {Component} from 'react';
import { Link } from 'react-router'
import { connect } from 'react-redux';
import { pushState } from 'redux-router';
import './index.scss';

let mapStateToProps = state => ({ location: state.router.location });
let mapDispatchToProps = dispatch => ({dispatch, pushState})

@connect(mapStateToProps, mapDispatchToProps)
export default class App extends Component {
  render() {
    return (
      <div className="app-wrapper">
        <header className="app-header">
          <Link to="/">
            <h1 className="app-header-brand">
              rent keepr
            </h1>
          </Link>
        </header>
        <main  className="app-main">
          {this.props.children}
        </main>
      </div>
    );
  }
};
