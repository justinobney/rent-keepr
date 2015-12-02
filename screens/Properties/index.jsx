// Property List Screen
import React, { Component } from 'react';
import { connect } from 'react-redux';
import { pushState } from 'redux-router';
import { Button, Table } from 'elemental';

import './index.scss';

import ContentPage from 'components/ContentPage';
import {getProperties} from '@redux/modules/properties'

let mapStateToProps = state => ({properties: state.properties});
let mapDispatchToProps = dispatch => ({dispatch, pushState})

@connect(mapStateToProps, mapDispatchToProps)
export default class PropertyList extends Component {
  componentWillMount() {
    this.props.dispatch(getProperties())
  }
  _renderRow(item){
    return (
      <tr key={item.id}>
  			<td>
  				<a href="javascript:;">{`${item.address1}, ${item.city}, ${item.state} ${item.zipcode}`}</a>
  			</td>
  			<td>{item.tenant}</td>
        <td>{item.rent}</td>
      <td>{item.current}</td>
  		</tr>
    );
  }
  render() {
    let properties = this.props.properties;
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
            			<th>Tenany</th>
            			<th>Rent</th>
            			<th>Current</th>
            		</tr>
            	</thead>
            	<tbody>
                {properties.items.map(::this._renderRow)}
            	</tbody>
            </Table>
          </main>
        </ContentPage>
      </div>
    );
  }
};
