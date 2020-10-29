import { Typography } from '@material-ui/core';
import { observer } from 'mobx-react';
import React from 'react';
import { useStyles } from '../styles/home';

export const Home = observer(() => {
    const classes = useStyles();
    return (
        <div className={classes.container}>
            <Typography variant='h2' className={classes.header}>Firewall Frontend</Typography>
            <Typography variant='h5'>this is a frontend of a firewall kernel module</Typography>
        </div>
    );
});
