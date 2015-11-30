// Property List Screen
import React, { Component } from 'react';
import { connect } from 'react-redux';
import { pushState } from 'redux-router';
import { Button, Table } from 'elemental';

import './index.scss';

import ContentPage from 'components/ContentPage';

let mapStateToProps = state => ({});
let mapDispatchToProps = dispatch => ({dispatch, pushState})

@connect(mapStateToProps, mapDispatchToProps)
export default class PropertyList extends Component {
  render() {
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
            		<tr>
            			<td>
            				<a href="javascript:;">123 Foo Ave, Denham Springs, LA 70817</a>
            			</td>
            			<td>John Smith</td>
                  <td>$700</td>
            			<td>Yes</td>
            		</tr>
                <tr>
            			<td>
            				<a href="javascript:;">123 Foo Ave, Denham Springs, LA 70817</a>
            			</td>
            			<td>John Smith</td>
                  <td>$700</td>
            			<td>Yes</td>
            		</tr>
                <tr>
            			<td>
            				<a href="javascript:;">123 Foo Ave, Denham Springs, LA 70817</a>
            			</td>
            			<td>John Smith</td>
                  <td>$700</td>
            			<td>No</td>
            		</tr>
                <tr>
            			<td>
            				<a href="javascript:;">123 Foo Ave, Denham Springs, LA 70817</a>
            			</td>
            			<td>John Smith</td>
                  <td>$700</td>
            			<td>Yes</td>
            		</tr>
                <tr>
            			<td>
            				<a href="javascript:;">123 Foo Ave, Denham Springs, LA 70817</a>
            			</td>
            			<td>John Smith</td>
                  <td>$700</td>
            			<td>Yes</td>
            		</tr>
            	</tbody>
            </Table>
          </main>
        </ContentPage>
      </div>
    );
  }
};
