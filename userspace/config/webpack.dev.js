const HtmlWebpackPlugin = require('html-webpack-plugin');
const webpack = require('webpack');
const path = require('path');

module.exports = {
    mode: 'development',
    devtool: 'inline-source-map',
    entry: {
        main: path.resolve('./src/index.jsx'),
    },
    output: {
        path: path.resolve('./build'),
        filename: '[name].bundle.js',
    },
    plugins: [
        new HtmlWebpackPlugin({
            template: path.resolve('./public/index.html'),
            filename: 'index.html',
        }),
        new webpack.HotModuleReplacementPlugin(),
    ],
    module: {
        rules: [
            {
                test: /\.(js|jsx)$/,
                exclude: /node_modules/,
                use: {
                    loader: 'babel-loader',
                    options: {
                        presets: ["react-app"],
                        plugins: [
                            ["@babel/plugin-proposal-decorators", { "legacy": true }],
                            ["@babel/plugin-proposal-class-properties", { "loose" : true }]
                        ]
                    }
                }
            },
            {
                test: /\.(?:ico|gif|png|jpg|jpeg)$/i,
                type: 'asset/resource'
            },
            {
                test: /\.(woff(2)?|eot|ttf|otf|svg|)$/,
                type: 'asset/inline'
            },
        ],
    },
    devServer: {
        historyApiFallback: true,
        contentBase: path.resolve('./build'),
        open: true,
        compress: true,
        hot: true,
        port: 3000,
    },
    resolve: {
        extensions: ['.tsx', '.ts', '.js', '.jsx'],
    }
}
