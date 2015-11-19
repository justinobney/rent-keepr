// Home Screen
import React, {Component} from 'react';
import { Link } from 'react-router'
import { connect } from 'react-redux';
import { pushState } from 'redux-router';
import './index.scss';

let mapStateToProps = state => ({});
let mapDispatchToProps = dispatch => ({dispatch, pushState})

@connect(mapStateToProps, mapDispatchToProps)
export default class Home extends Component {
  componentWillMount() {
    // const { dispatch, pushState } = this.props;
    // setTimeout(() => dispatch(pushState(null, '/about')), 2000);
  }
  render() {
    return (
      <section className="home-wrapper">
        <nav className="home-sub-navigation">
          <Link to="/about" className="home-sub-navigation-link">about</Link>
          <Link to="/about" className="home-sub-navigation-link">about</Link>
          <Link to="/about" className="home-sub-navigation-link">about</Link>
          <Link to="/about" className="home-sub-navigation-link">about</Link>
        </nav>
        <main>
          <h1>Home Page</h1>
        </main>
      </section>
    );
  }
};
