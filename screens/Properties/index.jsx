// Property List Screen
import React, { Component } from 'react';
import { connect } from 'react-redux';
import { pushState } from 'redux-router';
import { Alert, Button, Glyph, Spinner, Table } from 'elemental';

import './index.scss';

import ContentPage from 'components/ContentPage';
import {getProperties} from '@redux/modules/properties'

let mapStateToProps = state => ({properties: state.properties});
let mapDispatchToProps = dispatch => ({dispatch, pushState})

class PropertyList extends Component {
  componentDidMount() {
    this.props.dispatch(getProperties())
  }
  _renderTable(properties){
    return (
      <Table>
        <colgroup>
          <col width="" />
          <col width="" />
          <col width="100" />
          <col width="100" />
        </colgroup>
        <thead>
          <tr>
            <th>Address</th>
            <th>Tenant</th>
            <th>Rent</th>
            <th>Current</th>
          </tr>
        </thead>
        <tbody>
          {properties.items.map(this._renderRow)}
        </tbody>
      </Table>
    );
  }
  _renderRow(item, idx){
    let icon = item.current ? 'thumbsup' : 'thumbsdown';
    let type = item.current ? 'default' : 'danger';
    return (
      <tr key={`${item.id}_${idx}`}>
  			<td>
          <Button type="link" href={`#/properties/${item.id}`}>
            {`${item.address1}, ${item.city}, ${item.state} ${item.zipcode}`}
          </Button>
  			</td>
  			<td>{item.tenant}</td>
        <td>{`$${item.rent.toFixed(2)}`}</td>
        <td>
          <Glyph icon={icon} type={type} />
        </td>
  		</tr>
    );
  }
  render() {
    let {properties} = this.props;
    let content = null;

    if(properties.isFetching){
      content = <Spinner size="md" type="primary" />;
    } else if (properties.errorMessage){
      content = <Alert type="danger"><strong>Error:</strong> {properties.errorMessage}</Alert>
    } else {
      content = this._renderTable(properties);
    }

    return (
      <div className="property-list-wrapper">
        <ContentPage>
          <header className="content-page-header">
            <h1>Properties</h1>
            <Button type="hollow-primary" className="content-page-header-cta"
              href="#/properties/new">
              New Property
            </Button>
          </header>
          <main>
            {content}
          </main>
        </ContentPage>
      </div>
    );
  }
};

export default connect(mapStateToProps, mapDispatchToProps)(PropertyList);
