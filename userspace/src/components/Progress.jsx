import { LinearProgress } from '@material-ui/core';
import React from 'react';

import { useStyles } from '../styles/progress';

export const Progress = () => {
    const classes = useStyles();
    return (
        <LinearProgress color='secondary' className={classes.progress} />
    );
};
