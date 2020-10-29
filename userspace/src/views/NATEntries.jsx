import React, { useEffect, useState } from 'react';
import { api } from '../api';
import { Table } from '../components/Table';
import { Refresh } from '@material-ui/icons';

export const NATEntries = () => {
    const [natEntries, setNATEntries] = useState([]);
    const refresh = () => {
        setNATEntries(() => api.getNATEntries());
    };
    useEffect(refresh, []);
    return (
        <Table
            title='NAT Entries'
            data={natEntries}
            columns={[
                { title: 'LAN IP', field: 'lan_ip' },
                { title: 'LAN Port', field: 'lan_port' },
                { title: 'WAN Port', field: 'wan_port' },
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
