import React, { useEffect, useState } from 'react';
import { api } from '../api';
import { Table } from '../components/Table';
import { Refresh } from '@material-ui/icons';

export const Connections = () => {
    const [connections, setConnections] = useState([]);
    const refresh = () => {
        setConnections(() => api.getConnections());
    };
    useEffect(refresh, []);
    return (
        <Table
            title='Connections'
            data={connections}
            columns={[
                { title: 'Source IP', field: 'src_ip' },
                { title: 'Source Port', field: 'src_port' },
                { title: 'Destination IP', field: 'dst_ip' },
                { title: 'Destination Port', field: 'dst_port' },
                { title: 'Protocol', field: 'protocol' },
            ]}
            actions={[
                {
                    icon: () => <Refresh />,
                    tooltip: 'Refresh',
                    isFreeAction: true,
                    onClick: refresh
                },
            ]}
        />
    );
};
