import { Book, CompareArrows, Dns, Home, List } from '@material-ui/icons';
import { observer } from 'mobx-react';
import React, { useState } from 'react';

import { useStores } from '../hooks/useStores';
import { useStyles } from '../styles/frame';

import { AppBar } from './AppBar';
import { Menu } from './Menu';
import { Notifier } from './Notifier';
import { Progress } from './Progress';

const listItems = [
    { to: '/', text: 'home', icon: <Home /> },
    { to: '/rules', text: 'rules', icon: <List /> },
    { to: '/connections', text: 'connections', icon: <CompareArrows /> },
    { to: '/logs', text: 'logs', icon: <Book /> },
    { to: '/nat', text: 'nat', icon: <Dns /> },
];

export const Frame = observer(({ children }) => {
    const classes = useStyles();
    const { componentStateStore } = useStores();
    const [open, setOpen] = useState(false);

    const handleClick = () => {
        open && setOpen(false);
    };

    const toggleOpen = () => {
        setOpen((open) => !open);
    };

    return (
        <div className={classes.root}>
            <AppBar open={open} toggleOpen={toggleOpen} />
            <Menu items={listItems} open={open} toggleOpen={toggleOpen} />
            <main className={classes.content} onClick={handleClick}>
                {children}
            </main>
            {componentStateStore.progressOn && <Progress />}
            <Notifier />
        </div>
    );
});
