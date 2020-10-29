import React, { useEffect, useState } from 'react';
import { api } from '../api';
import { Table } from '../components/Table';
import { action, computed, makeObservable, observable, toJS } from 'mobx';
import { observer } from 'mobx-react';
import { ArrowDownward, ArrowUpward, Save } from '@material-ui/icons';

const CIDR_REGEX = /^([0-9]{1,3}\.){3}[0-9]{1,3}(\/([0-9]|[1-2][0-9]|3[0-2]))?$/;

const validators = {
    src_cidr: ({ src_cidr }) => typeof src_cidr === 'string' && (CIDR_REGEX.test(src_cidr) || src_cidr.toUpperCase() === 'ANY'),
    src_port: ({ src_port }) => Number.isInteger(src_port) && src_port >= 0 && src_port < 65536,
    dst_cidr: ({ dst_cidr }) => typeof dst_cidr === 'string' && (CIDR_REGEX.test(dst_cidr) || dst_cidr.toUpperCase() === 'ANY'),
    dst_port: ({ dst_port }) => Number.isInteger(dst_port) && dst_port >= 0 && dst_port < 65536,
    protocol: ({ protocol }) => typeof protocol === 'string' && ['TCP', 'UDP', 'ICMP', 'ANY'].includes(protocol.toUpperCase()),
}

export class RulesStore {
    composeKey({ src_ip, src_mask, dst_ip, dst_mask, src_port, dst_port, protocol }) {
        return `${src_ip}/${src_mask}:${src_port}-${protocol}-${dst_ip}/${dst_mask}:${dst_port}`;
    }

    checkRule(rule) {
        return !Object.values(validators).map((f) => f(rule)).includes(false);
    }

    formatRule({ src_cidr, dst_cidr, src_port, dst_port, protocol, action, log, start, end }) {
        const [src_ip, src_mask] = src_cidr.toUpperCase() === 'ANY' ? ['0.0.0.0', '0'] : src_cidr.split('/');
        const [dst_ip, dst_mask] = dst_cidr.toUpperCase() === 'ANY' ? ['0.0.0.0', '0'] : dst_cidr.split('/');
        return {
            src_ip,
            src_mask: src_mask === undefined ? 32 : +src_mask,
            dst_ip,
            dst_mask: dst_mask === undefined ? 32 : +dst_mask,
            src_port: +src_port,
            dst_port: +dst_port,
            protocol: protocol.toUpperCase(),
            action: !!action,
            log: !!log,
            start: ~~(+new Date(start) / 1000 % (60 * 60 * 24)),
            end: ~~(+new Date(end) / 1000 % (60 * 60 * 24)),
        };
    }

    @observable
    rules = [];

    constructor() {
        makeObservable(this);
    }

    @action
    setRules(rules) {
        this.rules = rules;
    }

    @action
    add(rule) {
        if (this.checkRule(rule)) {
            this.rules.push(this.formatRule(rule));
        }
    }

    @action
    delete(key) {
        this.rules.splice(key, 1);
    }

    @action
    update(key, rule) {
        if (this.checkRule(rule)) {
            this.rules[key] = this.formatRule(rule);
        }
    }

    @action
    exchange(key1, key2) {
        if (!this.rules[key1] || !this.rules[key2]) {
            return;
        }
        const rule = this.rules[key1];
        this.rules[key1] = this.rules[key2];
        this.rules[key2] = rule;
    }

    @computed
    get readableRules() {
        return this.rules.map(({ src_ip, src_mask, dst_ip, dst_mask, src_port, dst_port, protocol, action, log, start, end }, key) => ({
            key,
            src_cidr: `${src_ip}/${src_mask}`,
            dst_cidr: `${dst_ip}/${dst_mask}`,
            src_port,
            dst_port,
            protocol,
            action,
            log,
            start: new Date(946684800000 + start * 1000),
            end: new Date(946684800000 + end * 1000),
        }));
    }
}

export const Rules = observer(() => {
    const [rulesStore] = useState(() => new RulesStore());
    useEffect(() => {
        rulesStore.setRules(api.getRules());
    }, []);
    const handleSubmit = () => {
        api.sendRules(toJS(rulesStore.rules));
    }
    return (
        <Table
            title='Rules'
            data={rulesStore.readableRules}
            columns={[
                { title: 'Source CIDR', field: 'src_cidr', validate: validators.src_cidr },
                { title: 'Source Port', field: 'src_port', type: 'numeric', validate: validators.src_port },
                { title: 'Destination CIDR', field: 'dst_cidr', validate: validators.dst_cidr },
                { title: 'Destination Port', field: 'dst_port', type: 'numeric', validate: validators.dst_port },
                { title: 'Protocol', field: 'protocol', validate: validators.protocol },
                { title: 'Action', field: 'action', type: 'boolean', initialEditValue: false },
                { title: 'Log', field: 'log', type: 'boolean', initialEditValue: false },
                { title: 'Start', field: 'start', type: 'time', initialEditValue: new Date('2000-01-01 00:00:00') },
                { title: 'End', field: 'end', type: 'time', initialEditValue: new Date('2000-01-01 23:59:59') },
            ]}
            editable={{
                onRowDelete: async ({ key }) => rulesStore.delete(key),
                onRowAdd: async (rule) => rulesStore.add(rule),
                onRowUpdate: async (rule, { key }) => rulesStore.update(key, rule)
            }}
            actions={[
                {
                    icon: () => <Save />,
                    tooltip: 'Submit',
                    isFreeAction: true,
                    onClick: handleSubmit
                },
                {
                    icon: () => <ArrowUpward />,
                    tooltip: 'Move up',
                    onClick: (event, { key }) => {
                        rulesStore.exchange(key, key - 1);
                    }
                },
                {
                    icon: () => <ArrowDownward />,
                    tooltip: 'Move down',
                    onClick: (event, { key }) => {
                        rulesStore.exchange(key, key + 1);
                    }
                }
            ]}
        />
    );
});
