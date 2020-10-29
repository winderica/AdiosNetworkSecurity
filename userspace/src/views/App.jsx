import { CssBaseline, ThemeProvider } from '@material-ui/core';
import { LocationProvider, createMemorySource, createHistory, Router } from '@reach/router';
import { SnackbarProvider } from 'notistack';
import React from 'react';

import { Frame } from '../components/Frame';
import { theme, useStyles } from '../styles/global';

import { Connections } from './Connections';
import { Logs } from './Logs';
import { NATEntries } from './NATEntries';
import { Rules } from './Rules';
import { Home } from './Home';

const history = createHistory(createMemorySource("/"));

export const App = () => {
    useStyles();
    return (
        <CssBaseline>
            <ThemeProvider theme={theme}>
                <SnackbarProvider maxSnack={5}>
                    <LocationProvider history={history}>
                        <Frame>
                            <Router primary={false} component={({ children }) => <>{children}</>}>
                                <Home default />
                                <Rules path='rules' />
                                <Connections path='connections' />
                                <Logs path='logs' />
                                <NATEntries path='nat' />
                            </Router>
                        </Frame>
                    </LocationProvider>
                </SnackbarProvider>
            </ThemeProvider>
        </CssBaseline>
    );
};
