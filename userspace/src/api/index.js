const process = window.require('process');
const isDev = process.env.NODE_ENV === 'development';
const cwd = process.cwd();
const addon = window.require(isDev ? cwd + '/src/cpp/build/Debug/firewall-addon' : '../src/cpp/build/Release/firewall-addon');

export const api = new addon.NetlinkAPI();
