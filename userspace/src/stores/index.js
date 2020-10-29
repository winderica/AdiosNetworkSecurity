import { ComponentStateStore } from './componentState';
import { NotificationStore } from './notification';

export const stores = {
    notificationStore: new NotificationStore(),
    componentStateStore: new ComponentStateStore(),
};

export { ComponentStateStore, NotificationStore };
