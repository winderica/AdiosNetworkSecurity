import React, { useEffect, useState } from 'react';
import { api } from '../api';
import { Table } from '../components/Table';
import { ClearAll, Refresh } from '@material-ui/icons';

export const Logs = () => {
    const [logs, setLogs] = useState([]);
    const refresh = () => {
        setLogs(() => api.getLogs());
    };
    useEffect(refresh, []);
    const clear = () => {
        api.clearLogs();
        refresh();
    }
    return (
        <Table
            title='Logs'
            data={logs}
            columns={[
                { title: 'Source IP', field: 'src_ip' },
                { title: 'Source Port', field: 'src_port' },
                { title: 'Destination IP', field: 'dst_ip' },
                { title: 'Destination Port', field: 'dst_port' },
                { title: 'Protocol', field: 'protocol' },
                { title: 'Action', field: 'action' },
                { title: 'Time', field: 'timestamp' },
            ]}
            actions={[
                {
                    icon: () => <ClearAll />,
                    tooltip: 'Clear All',
                    isFreeAction: true,
                    onClick: clear
                },
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
