var webpack = require('webpack');
var path = require('path');
var ExtractTextPlugin = require('extract-text-webpack-plugin');


const resolve = require('path').resolve;
const _slice  = [].slice;
PROJECT_PATH = resolve(__dirname, './');

function inProject () {
  return resolve.apply(resolve, [PROJECT_PATH].concat(_slice.apply(arguments)));
}

module.exports = {
  entry: [
    'webpack-dev-server/client?http://0.0.0.0:9000', // WebpackDevServer host and port
    'webpack/hot/only-dev-server',
    './index.jsx' // Your appʼs entry point
  ],
  devtool: process.env.WEBPACK_DEVTOOL || 'source-map',
  output: {
    path: path.join(__dirname, 'public'),
    filename: 'bundle.js'
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
  module: {
    loaders: [
      {
        test: /\.jsx?$/,
        exclude: /(node_modules|bower_components)/,
        loaders: ['react-hot', 'babel?stage=0'],
      },
      { test: /\.json$/, loader: "json" },
      { test: /\.css$/, loader: 'style!css' },
      { test: /\.scss$/, loader: 'style!css?sourceMap!sass?sourceMap' }
    ]
  },
  sassLoader: {
    includePaths: [path.resolve(__dirname, "./scss")]
  },
  devServer: {
      contentBase: "./public",
      noInfo: true, //  --no-info option
      hot: true,
      inline: true
  },
  plugins: [
    new webpack.HotModuleReplacementPlugin(),
    new webpack.NoErrorsPlugin()
  ]
};
