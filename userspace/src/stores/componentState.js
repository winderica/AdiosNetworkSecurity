import { action, makeObservable, observable } from 'mobx';

export class ComponentStateStore {
    @observable
    progressOn = false;

    constructor() {
        makeObservable(this);
    }

    @action
    setProgress(on = true) {
        this.progressOn = on;
    }
}
