import { Link } from '@reach/router';
import React from 'react';

import { useStyles } from '../styles/anchor';

export const Anchor = ({ to, children }) => {
    const classes = useStyles();
    return <Link to={to} className={classes.link}>{children}</Link>;
};
