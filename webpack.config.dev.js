var path = require('path');
var webpack = require('webpack');

const resolve = require('path').resolve;
const _slice  = [].slice;
PROJECT_PATH = resolve(__dirname, './');

function inProject () {
  return resolve.apply(resolve, [PROJECT_PATH].concat(_slice.apply(arguments)));
}

module.exports = {
  devtool: process.env.WEBPACK_DEVTOOL || 'source-map',
  entry: [
    'webpack-hot-middleware/client',
    'babel-polyfill',
    path.resolve(__dirname, './index.jsx')
  ],
  // output: {
  //   path: path.join(__dirname, 'public'),
  //   filename: 'app.js'
  // },
  output: {
    path: path.join(__dirname, 'public'),
    filename: 'app.js',
    publicPath: '/static/'
  },
  resolve: {
    modulesDirectories: ['node_modules', './components'],
    extensions: ['', '.js', '.jsx'],
    alias: {
      components: inProject('components'),
      root: inProject(),
      '@redux': inProject('redux'),
      scss: inProject('scss'),
      screens: inProject('screens')
    },
    root:'/'
  },
  plugins: [
    new webpack.HotModuleReplacementPlugin(),
    new webpack.NoErrorsPlugin(),
    new webpack.DefinePlugin({//"compiler flags"
      __CLIENT__: true,
      __SERVER__: false,
      __DEVELOPMENT__: true,
      __DEVTOOLS__: true
      // 'process.env.NODE_ENV': 'production'
    })
  ],
  module: {
    loaders: [
      {
        test: /\.jsx?$/,
        exclude: /(node_modules|bower_components)/,
        loaders: ['react-hot', 'babel'],
      },
      { test: /\.json$/, loader: "json" },
      { test: /\.css$/, loader: 'style!css' },
      { test: /\.less$/, loader: 'style!css!less' },
      { test: /\.scss$/, loader: 'style!css?sourceMap!sass?sourceMap' }
    ]
  },
  sassLoader: {
    includePaths: [path.resolve(__dirname, "./scss")]
  },
};
