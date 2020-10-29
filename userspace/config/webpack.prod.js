const HtmlWebpackPlugin = require('html-webpack-plugin');
const TerserPlugin = require('terser-webpack-plugin');
const path = require('path');

module.exports = {
    mode: 'production',
    devtool: false,
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
                            ["@babel/plugin-proposal-class-properties", { "loose": true }]
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
    optimization: {
        minimize: true,
        minimizer: [new TerserPlugin()],
        runtimeChunk: {
            name: 'runtime',
        },
    },
    resolve: {
        extensions: ['.tsx', '.ts', '.js', '.jsx'],
    }
}
