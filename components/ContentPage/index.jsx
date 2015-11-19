import React, {Component} from 'react';
import './index.scss';

export default class ContentPage extends Component {
  render() {
    return (
      <section className={`content-page ${this.props.className || ''}`}>
        {this.props.children}
      </section>
    );
  }
};
